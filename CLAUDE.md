## Rules

- Track the model, tokens and cost of every LLM call.
- Keep the README up to date before every commit. A commit that changes behaviour, config, commands or tests must also update `README.md`, the only README. Check the test count after code edits. Keep the README free of conflicts with the code, and write it so that a person can read it.
- Use subagents for work that has no dependencies between its parts. Send the independent subagent calls in one message so they run in parallel. Do the work yourself when one part needs the result of another, or when it takes only a few tool calls.
- For a task with no open questions and no blockers, ask for the go-ahead early. Do not wait until its dependencies are done to ask. Once the go-ahead is given, start the task as soon as its dependencies are complete.
- The most important rule is the second one: keep the README current before every commit.
- Do not write outside the worktree.
- Always commit once per task, as soon as the task is done, so that no change is lost. Do not batch several tasks into one commit. Do not push unless asked.
- Keep `docs/tasks.md` current. It is the task list that lets an agent continue after a stop. Read it before you start work. Update a task's status and checklist whenever the task changes state, in the same commit.
- Always verify the task yourself before committing; use human gates only when there is no other option.

