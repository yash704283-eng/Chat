# Private room (Railway)

1. Push this folder to a **private** GitHub repo.
2. Railway > New Project > Deploy from GitHub repo.
3. Variables tab: add `CODE_A` and `CODE_B` (the two starting keys).
4. Settings > Networking > Generate Domain. Done.

Recommended: add a Volume mounted at `/data` and set variable `DATA_DIR=/data`,
so changed keys survive redeploys. Without it, a redeploy resets keys to CODE_A / CODE_B and clears the chat.
