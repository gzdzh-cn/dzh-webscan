package controlplane

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

func Serve(ctx context.Context, c Config, role string) error {
	if !validServiceRole(role) {
		return errors.New("当前可运行角色为 all、api、collector、notifier、websites、executor")
	}
	if c.Validate() != nil {
		if role == "executor" && !c.Executor.Enabled {
			return errors.New("executor 角色需要显式设置 executor.enabled 并配置部署信任资料")
		}
		return errors.New("中心启动配置无效")
	}
	store, e := Open(ctx, c)
	if e != nil {
		return e
	}
	defer store.DB.Close()
	var version int
	if e = store.DB.QueryRowContext(ctx, "SELECT max(version) FROM v3_schema").Scan(&version); e != nil || version != SchemaVersion {
		return errors.New("数据库尚未初始化或版本不兼容，请先执行数据库初始化")
	}
	launch := c
	c, activation, authority, e := store.resolveBootstrap(ctx, launch)
	if e != nil {
		return e
	}
	if activation > 0 {
		effectiveStore, err := store.openEffectiveBootstrap(ctx, c)
		if err != nil {
			return err
		}
		_ = store.DB.Close()
		store = effectiveStore
		defer store.DB.Close()
	}
	store.ExportDirectory = c.Central.ExportDirectory
	store.DB.SetMaxOpenConns(c.Database.MaxConnections)
	store.DB.SetMaxIdleConns(c.Database.MaxConnections)
	if role == "executor" && !c.Executor.Enabled {
		return errors.New("executor 角色需要显式设置 executor.enabled 并配置部署信任资料")
	}
	if e = store.BindCluster(ctx, c); e != nil {
		return e
	}
	// Lease ownership is per process, not just a stable machine name. During
	// rolling restarts an old and a new process must never share an epoch.
	bootstrap := c
	c.Central.Instance = runtimeInstance(c.Central.Instance)
	var executor *DeploymentRunner
	if role == "executor" || role == "all" && c.Executor.embedded() {
		executor, e = newDeploymentExecutor(ctx, store, c)
		if e != nil {
			return e
		}
	}
	var applications *configurationApplicationWorker
	if executor != nil && c.Executor.ApplicationsEnabled {
		runtime, err := newConfigurationCompositeRuntime(ctx, store, executor.Vault, launch, bootstrap, []string{role}, executor.Runtime)
		if err != nil {
			return err
		}
		applications = &configurationApplicationWorker{store: store, runtime: runtime, instance: c.Central.Instance}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, ready := withStartupReadiness(ctx, role, executor != nil, applications != nil)
	// Bind and load TLS before starting any worker. A bad listener must not
	// produce a startup receipt or leave background roles running on failure.
	var listener net.Listener
	var serverTLS *tls.Config
	if role == "api" || role == "all" {
		listener, e = net.Listen("tcp", c.Central.Listen)
		if e != nil {
			return errors.New("后台监听失败，请检查地址及端口占用")
		}
		defer listener.Close()
		if c.Central.CertFile != "" {
			pair, err := tls.LoadX509KeyPair(c.Central.CertFile, c.Central.KeyFile)
			if err != nil {
				return errors.New("后台 TLS 证书或私钥不可用")
			}
			serverTLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
		}
	}
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
		// Mark the process ended only after every role and the API listener have
		// drained. The heartbeat observer can finish before those workers do.
		if authority != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			_ = store.endBootstrapProcess(cleanup, authority, bootstrapProcess{Instance: c.Central.Instance, Member: launch.Central.Instance, Role: role, Activation: activation})
		}
	}()
	failures := make(chan error, 8)
	reportFailure := func(err error) {
		select {
		case failures <- err:
		case <-ctx.Done():
		}
	}
	if authority != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reportFailure(store.runBootstrapProcess(ctx, authority, launch, bootstrap, activation, c.Central.Instance, role, ready))
		}()
	}
	if executor != nil {
		wg.Add(1)
		go func() { defer wg.Done(); reportFailure(executor.Run(ctx)) }()
	}
	if executor != nil && c.NodePKI.Enabled && c.Executor.RulesFile != "" {
		runtime := executor.Runtime.(*SSHNodeRuntime)
		preparations := &webDeploymentWorker{store: store, config: bootstrap, trust: &deploymentTrust{vault: executor.Vault, release: runtime.Release, config: c.DeploymentTrust}, instance: c.Central.Instance}
		wg.Add(1)
		go func() { defer wg.Done(); reportFailure(preparations.Run(ctx)) }()
		monitoring := NewMonitoringApplicationWorker(store, bootstrap, preparations.trust, runtime, c.Central.Instance)
		wg.Add(1)
		go func() { defer wg.Done(); reportFailure(monitoring.Run(ctx)) }()
	}
	if applications != nil {
		wg.Add(1)
		go func() { defer wg.Done(); reportFailure(applications.Run(ctx)) }()
	}
	metrics := &Metrics{RawURL: c.Metrics.RawURL, WriteURL: c.Metrics.WriteURL, QueryURL: c.Metrics.QueryURL, HTTP: &http.Client{Timeout: 15 * time.Second}}
	if role == "websites" || role == "all" {
		worker := &WebsiteRunner{Store: store, Instance: c.Central.Instance}
		wg.Add(1)
		go func() { defer wg.Done(); reportFailure(worker.Run(ctx)) }()
	}
	if role == "notifier" || role == "all" {
		if store.HostQuota != nil {
			wg.Add(1)
			go func() { defer wg.Done(); reportFailure(RunHostWatchdogHistory(ctx, store, store.HostQuota)) }()
		}
		worker := &Notifier{Store: store, Instance: c.Central.Instance}
		wg.Add(1)
		go func() { defer wg.Done(); reportFailure(worker.Run(ctx)) }()
		// Test sends have their own single-attempt queue. Missing local Vault
		// material disables that queue, never the existing business notifier.
		if vault, err := OpenVault(c.DeploymentTrust.VaultKeyFile, c.DeploymentTrust.PreviousKeyFiles...); err == nil {
			tests := &NotificationTestWorker{Store: store, Vault: vault, Instance: c.Central.Instance}
			wg.Add(1)
			go func() { defer wg.Done(); reportFailure(tests.Run(ctx)) }()
		} else {
			op, stop := context.WithTimeout(ctx, 3*time.Second)
			_, _ = store.DB.ExecContext(op, `INSERT INTO v3_role_status(role,instance,heartbeat,error) VALUES('notification-tests',$1,clock_timestamp(),'测试通知的共享密钥不可用') ON CONFLICT(role,instance) DO UPDATE SET heartbeat=excluded.heartbeat,error=excluded.error,details='{}'::jsonb`, c.Central.Instance)
			stop()
		}
	}
	if role == "collector" || role == "all" {
		worker := &Collector{Store: store, Config: c, Metrics: metrics}
		wg.Add(1)
		go func() { defer wg.Done(); reportFailure(worker.Run(ctx)) }()
	}
	if role == "api" || role == "all" {
		api := NewAPI(store, bootstrap)
		api.Config = c
		api.Metrics = metrics
		wg.Add(1)
		go func() { defer wg.Done(); store.RunHousekeeping(ctx, c.Central.Instance) }()
		wg.Add(1)
		go func() { defer wg.Done(); store.RunRetention(ctx, c.Central.Instance) }()
		wg.Add(1)
		go func() { defer wg.Done(); api.RunSummary(ctx) }()
		srv := &http.Server{Addr: c.Central.Listen, Handler: api, TLSConfig: serverTLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			runtimeReady(ctx, "api")
			if serverTLS != nil {
				err = srv.ServeTLS(listener, "", "")
			} else {
				err = srv.Serve(listener)
			}
			reportFailure(err)
		}()
		defer func() {
			cancel()
			shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			_ = srv.Shutdown(shutdown)
		}()
	}
	select {
	case <-ctx.Done():
		return nil
	case e := <-failures:
		cancel()
		if e == context.Canceled || e == http.ErrServerClosed {
			return nil
		}
		return e
	}
}

func runtimeInstance(configured string) string {
	if len(configured) > 96 {
		configured = configured[:96]
	}
	return configured + "-" + token()[:20]
}
