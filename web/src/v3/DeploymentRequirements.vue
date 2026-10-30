<script setup lang="ts">
withDefaults(defineProps<{mode?:'docker'|'native'; compact?:boolean}>(),{mode:'docker',compact:false})
</script>
<template>
 <section class="deployment-requirements" aria-label="端口与环境要求"><strong>端口与环境要求</strong><ul><li>子服务器放行入站 TCP 22、19100，仅允许主服务器访问。</li><li>云安全组、宝塔防火墙和系统防火墙都要检查。自定义端口以实际配置为准。</li></ul><p>需 Linux amd64、root SSH 登录，监控目录存在且可访问。</p><p>{{ mode === 'native' ? '直接运行 Go：需要 systemd ≥231 及 CPU／内存资源控制，无需 Docker。' : 'Docker 单容器：需要可用的 Docker 引擎。' }}</p><p v-if="!compact" class="small muted">v3 由主控主动采集；旧推送节点迁移完成前保留其原通信端口。</p></section>
</template>
