# ZeroChannel

ZeroChannel 是一个纯浏览器运行的加密小工具：接收者生成密钥和加密链接，发送者打开链接输入明文，浏览器在本地完成加密并生成可传回的密文链接。

它不需要账号、服务器、数据库或网络请求。密钥和明文不会离开当前浏览器。

> Generate. Encrypt. Decrypt. No channel. Just crypto.

## 适合谁

ZeroChannel 适合需要临时、安全地传递一段秘密的人，例如：

- 把一次性口令、邀请码、配置片段或短文本发给指定接收者。
- 希望用静态网页完成公钥加密，但不想依赖聊天平台、后端服务或账号系统。
- 想审计一个体量很小、行为清楚的浏览器端加密工具。

它不适合大文件传输、长期密钥托管、团队权限管理，或需要合规审计记录的生产流程。

## 功能

- 在浏览器中生成 ED25519 密钥对。
- 复制私钥，并生成包含公钥的加密链接。
- 使用接收者公钥加密一段文本。
- 生成可直接打开的密文链接，便于传回接收者。
- 使用私钥解密收到的密文。
- 通过 URL fragment 保存模式、公钥和密文，避免把敏感参数发送给服务器。
- 使用严格的 Content Security Policy，禁止外部脚本、图片、媒体、连接和表单提交。

## 在线使用

如果 GitHub Pages 已启用，可以访问：

```text
https://zccz14.github.io/ZeroChannel/
```

也可以克隆仓库后在本地运行，见下方“本地开发”。

## 使用流程

### 接收者

1. 打开 ZeroChannel。
2. 选择“我要接收秘密”。
3. 点击“生成密钥对”。
4. 复制并妥善保存私钥。私钥丢失后，收到的密文无法恢复。
5. 复制加密链接，并发送给对方。
6. 收到密文链接后打开，粘贴或确认私钥，点击“解密内容”。

### 发送者

1. 打开接收者发来的加密链接。
2. 确认页面已读取接收者公钥。
3. 输入要传递的秘密。
4. 点击“加密并复制密文”。
5. 把复制出的密文链接发回给接收者。

## 加密方式

ZeroChannel 使用混合加密：

- 每条消息随机生成一把 256-bit AES-GCM 内容密钥。
- 正文使用 Web Crypto API 的 AES-GCM 加密。
- 内容密钥使用接收者公钥保护。
- 页面生成 ED25519 密钥，并在加密时通过 `ed2curve` 转换为 Curve25519。
- 公钥加密部分使用 `tweetnacl` 的 `box` 原语。
- 密钥以 base58 编码，密文以 base64url 编码。

安全级别约为 128-bit。欢迎进行安全审计和改进建议。

## 安全边界

ZeroChannel 的目标是“本地加密，不托管秘密”。请注意：

- 私钥只应由接收者保存，不要发给任何人。
- 浏览器、操作系统、剪贴板和扩展程序如果已经被攻破，ZeroChannel 无法提供额外保护。
- 链接里的密文不是秘密存储方案；请通过你信任的渠道传递。
- 不要把它当作密码管理器或长期密钥管理系统。
- 使用在线版本时，请确认访问的是可信来源，并优先使用 HTTPS。

## 本地开发

### 环境要求

- Node.js 24 推荐。GitHub Pages 工作流使用 Node.js 24。
- npm。

### 安装依赖

```bash
npm ci
```

### 启动开发服务器

```bash
npm run dev
```

### 构建生产版本

```bash
npm run build
```

### 预览构建结果

```bash
npm run preview
```

## 项目结构

```text
.
├── index.html              # 页面结构与安全策略
├── src/
│   ├── main.js             # 密钥生成、加密、解密和 URL 状态逻辑
│   └── styles.css          # 页面样式
├── PRODUCT.md              # 产品定位和设计原则
├── .github/workflows/      # GitHub Pages 部署流程
└── dist/                   # 构建产物
```

## 依赖

- [`vite`](https://vite.dev/)：开发服务器和构建工具。
- [`tweetnacl`](https://github.com/dchest/tweetnacl-js)：NaCl 加密原语。
- [`ed2curve`](https://github.com/dchest/ed2curve-js)：ED25519 到 Curve25519 的密钥转换。

## 贡献

欢迎提交 issue、PR 和安全审计反馈。贡献时建议优先关注：

- 加密流程是否更容易被普通用户正确使用。
- 错误提示是否准确、克制、可操作。
- 是否保持“无服务器、无遥测、无隐藏网络依赖”。
- 可访问性、键盘操作和移动端体验。

提交代码前请至少运行：

```bash
npm run build
```

## 部署

仓库包含 GitHub Pages 工作流。推送到 `main` 后，GitHub Actions 会执行：

```bash
npm ci
npm run build
```

然后把 `dist` 发布到 GitHub Pages。

## 许可证

MIT License。详见 [LICENSE](./LICENSE)。
