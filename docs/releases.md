# 自动测试和 Release

[GitHub Actions 工作流](../.github/workflows/ci-release.yml) 负责测试和发布 wheel。

## 触发方式

- PR：自动检查代码格式、运行 Ruff，并在 Linux / Python 3.14 上测试。
- 推送 `master`：同样检查；全部通过后自动创建 GitHub Release，上传 wheel。
- Actions 页面手动运行 `CI and Release`：选择 `master` 时会在检查通过后发布；
  选择其他分支时只测试。

测试会先通过 `uv sync --locked --dev` 安装锁定依赖，构建 wheel 后用其替换 editable 安装，
再对实际安装的 wheel 运行完整 pytest。启用 asyncio debug、Python dev 模式和 `-W error`，
同时打开 DEBUG 日志，覆盖 Linux socket/pipe/splice 的本机网络测试。
CI 不下载或运行文档中的 Xray/V2Fly 外部联调二进制。

仅发布 job 获得 `contents: write`，PR 测试保持只读。使用 GitHub 自带的 `GITHUB_TOKEN`
创建 Release，无需配置 PyPI 凭据或额外的 PAT；仓库需要允许 Actions 运行和该写入权限。
不会上传到 PyPI。

## 版本

格式为 `年.月.日.序号`，按分配版本时的 UTC 日期计算，例如：

```text
2026.10.24.1
2026.10.24.2
2026.10.25.1
```

每天从 1 开始，取现有同日标签中最大序号加 1，不按字符串排序。
月份、日期不补零，以保持 Python 包版本的标准表示，例如 `2027.1.2.1`。
Release 标签为 `v2026.10.24.1`，wheel 的文件名和包元数据使用 `2026.10.24.1`。

发布 job 串行运行，并在分配版本前重新获取标签，防止两个 job 使用相同序号。
同一提交可以通过手动运行再次发布，仍使用新序号；如果失败前已生成标签，后续也会跳过
已占用的序号，不覆盖旧版本。GitHub 默认只保留一个待执行的同组 job，频繁推送时较早的
待发布任务可能被后来的任务替换；已经执行的发布不会被取消。

构建时通过 `uv version --no-sync` 更新临时工作目录中的 `pyproject.toml` 和 `uv.lock`，
不自动向 `master` 提交版本修改。因此仓库中的开发版本保持原样；从 Git tag 安装源码时
仍会使用源码声明的开发版本，日期版本以 Release wheel 为准。
标签指向触发并通过测试的确切提交，不随发布过程中 `master` 的移动而改变。
发布前会安装日期版本的 wheel，检查可导入且元数据版本与标签一致。

## 下载和安装

在仓库的 Releases 页面下载 `.whl`，在需要使用它的 uv 项目中执行：

```bash
uv add /absolute/path/to/socks5_kit-2026.10.24.1-py3-none-any.whl
```

包仍要求 Linux 和 Python 3.14；`py3-none-any` 只表示 wheel 不包含编译扩展。

## 本地检查

```bash
uv sync --locked --dev
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv build --wheel --no-sources --clear
uv pip install --reinstall dist/*.whl
PYTHONASYNCIODEBUG=1 uv run --no-sync python -X dev -m pytest -q -W error --log-level=DEBUG
```

以上测试 wheel 后，可用 `uv sync --locked --dev` 恢复 editable 开发安装。
`uv run --no-project python tools/release_version.py` 只打印本地已获取标签对应的下一个版本，
不会修改版本或发布。标准库脚本有日期切换、数值序号及无关标签等自动化检查。

实现使用 [uv 的 Actions 集成](https://docs.astral.sh/uv/guides/integration/github/)、
[GitHub 并发分组](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
以及 [GitHub CLI Release](https://cli.github.com/manual/gh_release_create)。
