package config

import "webscan/internal/assets"

// Help is embedded so bootstrap needs neither private YAML nor network access.
func Help() string {
	b, _ := assets.Files.ReadFile("configuration-example.yaml")
	return "参数填写说明（仅示例，不读取实际配置，不连接服务器）\n" +
		"请从完整示例复制，再替换示例 IP、SSH 路径及飞书凭据。\n" +
		"默认开启飞书及加签：webhook_url 与 signing_secret 必填。\n" +
		"node_defaults 为公共设置；nodes 中映射合并、列表整体替换。\n" +
		"字符串用引号，开关用 true/false，整数不加引号，空列表用 []。\n" +
		"以下列出全部参数的作用、单位、填写示例及兼容限制：\n\n" + string(b)
}
