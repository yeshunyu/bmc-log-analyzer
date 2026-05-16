## ADDED Requirements

### Requirement: test-proposal-generation
proposal artifact 能被正确识别为已完成状态。

#### Scenario: proposal status check
- **WHEN** 执行 `openspec status --change <name> --json`
- **THEN** proposal 的 status 为 "done"
