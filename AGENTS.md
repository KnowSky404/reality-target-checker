# 项目开发约束

本文件适用于整个仓库。所有功能迭代、问题修复、重构、文档、配置和 CI 变更均遵循以下流程；对本文件的修改也不例外。

默认交付顺序：创建独立 worktree 和任务分支 → 开发并验证 → 本地 review、修复并提交 → 对最终 HEAD 完成全分支本地 review → 推送分支并创建 PR → 等待并处理当前 HEAD 的 Codex 机器人 review 与 CI → Rebase and merge → 确认合并并清理任务分支与 worktree。后续修复必须重新经过验证、本地 review、推送和机器人 review。

## 1. 在独立 worktree 中开发

- 开始修改前，检查工作区状态，更新远程引用，从最新的 `origin/main` 创建任务分支和独立 worktree。分支按用途命名，例如 `feat/<topic>`、`fix/<topic>`、`docs/<topic>`。
- worktree 放在仓库外的相邻目录，避免污染主工作目录。例如，在主工作目录执行（将 `<topic>` 替换为任务名）：

  ```bash
  git fetch --prune origin
  git worktree add -b docs/<topic> ../reality-target-checker-<topic> origin/main
  ```

- 所有编辑、提交、检查和本地 review 均在任务 worktree 中执行。同一 PR 的后续修复继续使用原 worktree 和分支。
- 禁止直接在主工作目录或 `main` 上开发、提交变更或直接推送 `main`。不得覆盖用户已有改动，也不得清理其他任务的分支或 worktree。

## 2. 每次推送和提交 PR 前先本地 review

- **每次 `git push`（包括修复后的再次推送、必要的强制更新），以及每次创建或更新 PR 前，必须先执行本地 `/review`，解决发现的问题，再复查至没有未解决问题。**
- 在 Codex 交互界面使用 `/review`，选择相对 `origin/main` 审查整个任务分支。非交互环境使用 `codex review --base origin/main`。如有未提交内容，还须用 `/review` 的未提交变更选项或 `codex review --uncommitted` 覆盖暂存、未暂存和未跟踪文件。
- review 必须覆盖本次 PR 的完整差异，不能只看最后一次提交。review 后有任何文件修改、提交追加、amend、rebase 或冲突解决，必须重新检查和 review；旧结果不能用于新内容。
- 提交前的未提交变更 review 不能代替最终 HEAD 的 review。完成提交后，必须再次执行 `codex review --base origin/main`（或交互界面的等效操作），并记录基线 SHA、当前 HEAD SHA、审查范围和结论；最终 review 后不再修改文件或提交，才可推送、创建或更新 PR。
- 根据变更运行必要验证。代码和测试变更至少执行 `bash scripts/check.sh`；涉及打包时还需执行 `bash scripts/package-release.sh "v$(bash reality-target-checker.sh --version)"`。纯文档变更检查差异、链接和命令的一致性，并执行 `git diff --check`。
- 本地 `/review` 不可用、执行失败或验证失败时，先排查并如实说明阻塞，不能跳过门禁、用自己的简单浏览代替，或声称已通过。

## 3. 推送分支并创建 PR

- 完成相应验证和本地 review，提交变更，再通过最终 HEAD 的全分支本地 review 后，推送任务分支并向 `main` 创建 PR。最终 review 必须覆盖实际推送的提交；任务交付必须包含 PR，不能只保留本地修改或远程分支。
- PR 描述写明问题、最终行为或约束变化、验证命令及结果，以及本地 review 的范围、基线 SHA、HEAD SHA 和结论；使用 `.github/pull_request_template.md` 记录，合并前补充机器人 review 的证据链接与对应 HEAD SHA。
- 已发布分支确需 rebase 时，仅使用 `--force-with-lease`，不得使用 `--force`，并在推送前重新完成本地检查和 review。

## 4. 等待并处理 Codex 机器人 review

- 创建 PR 或推送新提交后，主动跟进 Codex 机器人的 review。若未自动触发，按仓库现有机制请求 review；需要手动触发时可在 PR 中发送 `@codex review`。
- 检查正式 review、行内评论、PR 讨论及 CI 状态。必须有可核实的 review 完成信号，并确认审查对应当前 PR HEAD；无评论、等待超时、仍在排队或旧提交上的通过结果均不代表本轮通过。
- 记录机器人 review 的提交或评论链接及其对应的提交 SHA；若结果未直接标明 SHA，须从审查记录或明确关联该提交的上下文核实，无法对应当前 HEAD 时继续排查，不得据此合并。
- 对 review 意见逐项修复；认为不适用时给出可核实的理由并完成讨论，不得无依据忽略或直接标记解决。修复后重新执行“验证 → 本地 `/review` → 推送 → 等待机器人 review”，直到当前提交没有未解决问题。
- 机器人不可用、额度耗尽或结果不明确时，保留 PR 和分支，报告阻塞并继续可执行的排查；不得默认为 review 通过或自动合并。

## 5. Rebase 合并并清理

- 只有当前 HEAD 的本地 review、Codex 机器人 review 均已完成且无未解决问题、所需 CI 检查通过、仓库审批要求满足且无合并冲突，才可合并。
- 合并前再次核对远程 PR HEAD 与已审查提交一致。只使用 GitHub 的 **Rebase and merge**，在支持时绑定预期 HEAD SHA，避免误合并未经审查的新提交；不得改用 squash、merge commit 或绕过分支保护。
- 若需更新基线或解决冲突，在任务 worktree 中完成，并重新走完整检查和 review 流程。
- 上述条件满足后，主动完成合并和清理，无需用户重复授权；用户明确要求暂缓时遵循其要求。
- 确认 GitHub 上 PR 状态为已合并后，删除本次任务对应的远程分支；再从主工作目录移除本次任务的干净 worktree，删除本地任务分支，并在主工作目录干净时以 fast-forward 同步 `main`。
- 清理前再次确认远程任务分支仍指向已审查的源 HEAD；若出现额外提交，保留分支并说明。删除远程分支时优先使用 GitHub 删除分支接口，避免为清理动作重新推送或误改其他引用。
- Rebase 合并会改变提交 SHA，不能仅凭 `git branch --merged` 判断是否已合并。删除本地分支前核对 PR 的合并状态、已审查的源 HEAD 与本地分支一致，并确认没有未推送提交；仅在这些核对通过后，才可使用 `git branch -D` 清理。
- worktree 有未保存改动或分支出现额外提交时保留并说明，不得强制移除。最后报告 PR 链接、检查和 review 结果、合并及清理状态。

## Cloudflare 工具

与 Cloudflare 交互时使用 `cf` CLI；如果项目存在 Wrangler 配置文件，则使用 Wrangler。
