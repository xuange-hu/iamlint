# iamlint

[![CI](https://github.com/xuange-hu/iamlint/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/iamlint/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-252%20passing-brightgreen)](https://github.com/xuange-hu/iamlint/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen)](https://github.com/xuange-hu/iamlint/blob/main/pyproject.toml)

**AWS IAM 策略审计：每条结论都带行号、列号和原始字节。**

49 条规则、零依赖、第二遍扫描会把你的 statement **合起来**看，外加一个不需要
AWS 账号就能跑的实验场。

```console
$ iamlint policies/
== policies/ci-runner.json
[CRIT] IAM030  凭据签发 + 策略写入：完整提权链
    where : policies/ci-runner.json:7:17 (/Statement/0/Action)
    saw   : 'iam:CreateAccessKey' (statement 0) + 'iam:AttachUserPolicy' (statement 1)
    with  : policies/ci-runner.json:13:18 (statement 1)
    fix   : 拆掉这对组合：保留其中一个、收窄范围，或删掉。
    ref   : MITRE ATT&CK T1078.004 Valid Accounts: Cloud Accounts / AWS privesc primitives
```

每条结论四行——**where / saw / fix / ref**——审查者可以照着文件自己复核，不
必信任工具。只有两条 statement 合起来才成立的结论会多一行 `with`，点名另一
条：因为「删掉这两个里的一个」在看不到对方时没法下手。

## 为什么要第二遍

这条策略一条一条读，哪条都不吓人：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "RotateKeys", "Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*"},
    {"Sid": "AttachPol",  "Effect": "Allow", "Action": "iam:AttachUserPolicy", "Resource": "*"}
  ]
}
```

`iamlint` 会给出 `IAM030`（critical），点名两条，并让你拆开这对组合。八种
提权形态都是这么查出来的（`IAM030`-`IAM037`）：凭据签发 + 策略写入、建角色 +
写策略、策略版本劫持、`iam:PassRole` + Lambda/EC2/ECS/Glue、改信任策略 +
AssumeRole、改密码 + 写策略、拆权限边界 + 写策略。

`--bundle` 把同样的逻辑跨**文件**执行——对一个 principal 来说，真正要紧的是
挂在它身上的全部策略的并集。

## 三步跑通

```bash
pip install iamlint          # 或：pipx install iamlint
iamlint ./policies           # 1. 指向一个文件或目录
iamlint demo                 # 2. 看全部 49 条规则触发，不需要 AWS 账号
iamlint lab --out ./iam-lab  # 3. 六个练习，每个只坏在一处
```

没有额外依赖，没有配置，不需要凭证。demo 和 lab 读的都是仓库里带的文件：
**不会有任何网络请求离开你的机器**。

## 命令

| 命令 | 作用 |
|---|---|
| `iamlint PATH...` | 扫描文件/目录（`.json`），有结论时退出码 1 |
| `iamlint demo` | 内置坏策略：49 条规则全覆盖，离线可跑 |
| `iamlint lab [--out DIR]` | 六个挑战 + README，并验证它们确实被抓到 |
| `iamlint rules [--category CAT]` | 规则清单 |
| `--json` / `--compact` | 机器可读 / 每条一行 |
| `--sarif FILE` | SARIF 2.1.0，用于 GitHub code scanning |
| `--min-severity`、`--fail-on` | 噪音下限与 CI 门禁 |
| `--ignore IAM071` / `.iamlint-ignore` | 抑制（JSON 没法写注释） |
| `--only`、`--skip` | 按类别过滤 |
| `--bundle` | 把所有输入当成一个 principal 的 attached 策略 |
| `--no-graph` | 只跑第一遍 |

退出码：`0` 干净，`1` 存在不低于 `--fail-on` 的结论，`2` 用法错误。

CI 里这样用：

```yaml
- name: IAM 策略审计
  run: |
    pip install iamlint
    iamlint policies/ --sarif iamlint.sarif --fail-on high
- name: 上传
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: iamlint.sarif }
```

## 规则（49 条）

| 类别 | 编号 | 看什么 |
|---|---|---|
| wildcard | IAM001-008 | `Action: "*"`、`iam:*`、`Resource: "*"`、`Principal: "*"`、`NotAction`/`NotResource`、`iam:Create*`、任意角色 AssumeRole |
| escalation | IAM010-020 | 公开提权路径都是由这 11 个原语拼出来的 |
| graph | IAM030-037 | statement 之间的组合（`--bundle` 下跨文件） |
| trust | IAM040-045 | 公开信任、缺 `ExternalId`、通配账号、通配服务、OIDC/SAML 未钉住 sub |
| condition | IAM050-054 | `/0` 源 IP、条件值带通配、MFA 缺席、`Null`、完全没有条件 |
| resource | IAM060-064 | 缺 Resource、非 ARN、密钥类服务上的 `*通配` 账号/区域 |
| hygiene | IAM070-075 | 旧 Version、缺/重 Sid、重复 JSON 键、语法错误、体积逼近配额 |

`iamlint rules` 看完整清单，`iamlint rules --category trust` 按类别过滤。

## 和别家有什么不一样

- **零依赖**。JSON 解析器是手写的，保留每个值的行、列和 JSON Pointer，所以
  结论指向的是某个字节，不是某个文件。AWS 会静默忽略的那些错误它也会报：
  重复键（后者生效）、尾逗号、注释。
- **两遍扫描**。多数 IAM 扫描器一次只看一条 statement。真正让你丢账号的那条
  结论，活在两条 statement **之间**。
- **自带实验场**。`iamlint lab` 写出六个按真实评审最容易漏的方式写坏的策略，
  并验证工具确实抓得到。
- **MCP server**。`pip install "iamlint[mcp]"` 后 Claude Code / Cursor / Cline
  可以直接调六个工具（`iamlint_scan_text`、`iamlint_scan_path`、
  `iamlint_privilege_paths`、`iamlint_rules`、`iamlint_explain`、`iamlint_demo`）。
- **SARIF 2.1.0**，规则元数据由规则表生成，结论能直接落到 PR 里。

## 安装

```bash
pip install iamlint                        # 零依赖
pip install "iamlint[mcp]"                 # 带 MCP server
pip install "git+https://github.com/xuange-hu/iamlint.git"   # 直接装 main
```

源码：

```bash
git clone https://github.com/xuange-hu/iamlint
cd iamlint
pip install -e .
pip install pytest && python -m pytest -q      # 252 tests
```

Python 3.10+。运行时不需要 AWS 账号、不需要凭证、不联网。

> **PyPI 说明**：Actions 里的 `Publish to PyPI` 是红的，原因是尚未在 PyPI 为
> 该项目注册 Trusted Publishing——工作流本身是对的，走的是 OIDC。在那之前用
> 上面的 git 安装方式即可；一旦项目注册完成，`pip install iamlint` 立刻可用。

MIT 许可。
