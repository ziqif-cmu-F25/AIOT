# libcoap Milestone 2 — 直接上手包

> 按顺序做，不用想。`【填】` = 你要填的地方。总时长 ≈ 3.5–4h。
> 记录全部写进同目录 `log.csv`，transcript 存成 `transcripts/<session_id>.md`。

---

## 0. 实验到底比什么（一句话，报告里也用这句）

> We do not compare human vs. AI speed. The Stage 1 manual analysis provides **ground truth**; we evaluate, step by step, how closely an AI model reproduces each step's output under three controlled information conditions (C0/C1/C2), with the human operator held constant under fixed intervention rules.

| 条件 | AI 能拿到什么 | 测的步骤 |
|---|---|---|
| **C0** one-shot | 一组固定源码文件（含真漏洞文件 + 诱饵文件），一次回答 | Static analysis / localization |
| **C1** tool-mediated | 只给文件树；AI 每轮可请求 `READ`/`GREP`，你原样返回 | Target understanding + static analysis |
| **C2** runtime evidence | C1 的能力 + ASan 报告 | Root-cause analysis + fix 位置（+可选 patch 验证） |

C1 里“你当工具执行器”= 手动版 Stage 3 bounded agent，正好留作后续素材。

---

## 1. Ground truth（20 min）— 先填，之后不许改

| 项 | 内容 |
|---|---|
| CVE / issue ID | 【填】 |
| libcoap 版本 / commit | 【填】 |
| 漏洞文件 | 【填】 |
| 漏洞函数 | 【填】 |
| 行号范围 | 【填】 |
| Bug class | 【填，如 heap-buffer-overflow read】 |
| Root cause（一句话） | 【填：缺了什么检查 / 哪个长度没校验】 |
| 触发条件 | 【填：什么样的 PDU / option 字段】 |
| 正确修复位置 | 【填：函数 + 大致行】 |
| ASan 报告 top 3 frames | 【填】 |
| Oracle 命令 | 【填，如 `./poc_runner poc.bin` → ASan crash = vulnerable；无 crash + `make check` 通过 = fixed】 |

**R_score 评分要点（从上表抽 3 个 key facts）：**
- K1 bug class：【填】
- K2 缺失的检查 / 错误的长度计算：【填】
- K3 触发的输入特征：【填】

---

## 2. 准备材料（20 min）

### 2.1 C0 文件包
- 选 **5–6 个文件**：1 个真漏洞文件 + 4–5 个**同类职责**的诱饵（也做解析/长度处理的，比如 pdu/option/block/net/encode 相关）。
- 记下文件列表：【填】
- 总长度太大塞不进 context → 去掉诱饵里最长的，但**真文件必须完整**。
- C0-1 和 C0-2 用同一个包，文件顺序打乱一次（防位置偏差）。

### 2.2 C1 文件树
```bash
cd <libcoap_src> && find src include -name '*.[ch]' | sort > ../filetree.txt
```

### 2.3 C2 ASan 报告
- 跑一次 PoC 拿完整 ASan 输出，存 `asan.txt`。
- **只给报告，不给 PoC 文件本身。**

### 2.4 Recall probe（5 min，算入 C0 之前）
新开对话，只问：
```
What do you know about vulnerability 【CVE-ID】 in libcoap? Which file and function is affected, and what is the root cause? Answer only from memory; say "I don't know" if unsure.
```
记录：说中文件/函数？说中 root cause？→ 写进报告 Limitations (3)。
**说中了也继续做**，只是结论里要注明“可能是回忆”。

---

## 3. 干预规则（每个 session 前看一眼）

**只允许以下原话（可复制）：**
1. `Continue.`
2. `Here is the output of your request:` + 原样输出
3. `Your request could not be executed (file not found / too large). Please make a different request.`
4. `Please give your final answer in the required format.`（超过轮数上限时）

**禁止**：提任何函数/文件/字段名；说“接近了/不对”；改写 prompt；给额外提示。
违反一次 → `rule_violations` +1，session 标注，**结果单独报告不算入主表**。

**上限**：C1/C2 最多 **15 轮**请求；一次 READ 最多 300 行。

---

## 4. 固定 Prompts（不许改）

### C0 — one-shot localization
```
You are performing a security code review of libcoap, a C implementation of the CoAP protocol used in IoT devices. Untrusted input arrives as CoAP messages from the network.

Below are several source files from libcoap 【版本】. Identify memory-safety vulnerabilities that can be triggered by a remote attacker sending crafted CoAP messages.

Output format:
CANDIDATES (ranked, most likely first, max 5):
1. file: / function: / approx lines:
   bug class:
   reasoning (quote the specific code lines involved):
   triggering input characteristics:
2. ...

<<<FILES>>>
【粘贴文件包，每个文件前加 ==== path/to/file.c ====】
```

### C1 — tool-mediated localization
```
You are performing a security code review of libcoap 【版本】, a C implementation of the CoAP protocol used in IoT devices. Untrusted input arrives as CoAP messages from the network.

Goal: find a memory-safety vulnerability that a remote attacker can trigger with a crafted CoAP message.

You cannot see the code directly. Each turn, issue exactly ONE request:
  READ <path> <start_line> <end_line>     (max 300 lines)
  GREP <pattern> [<path>]
  FINAL
I will return the raw output and nothing else. You have at most 15 requests.

Before each request, write one line: HYPOTHESIS: <your current hypothesis>.
When you issue FINAL, give your answer in this format:
CANDIDATES (ranked, max 5):
1. file / function / approx lines / bug class / reasoning quoting code / triggering input characteristics

File tree:
【粘贴 filetree.txt】
```
你执行 GREP 用：`grep -rn '<pattern>' src include | head -50`；READ 用：`sed -n 'S,Ep' <path>`（输出带行号：`nl -ba <path> | sed -n 'S,Ep'`）。

### C2 — runtime evidence → root cause
```
You are analyzing a crash in libcoap 【版本】, a C implementation of the CoAP protocol used in IoT devices. A crafted CoAP message received from the network produced the AddressSanitizer report below.

You may request source code, one request per turn:
  READ <path> <start_line> <end_line>     (max 300 lines)
  GREP <pattern> [<path>]
  FINAL
At most 15 requests. Before each request write one line: HYPOTHESIS: <current hypothesis>.

At FINAL, answer:
ROOT CAUSE: (what check is missing or what computation is wrong; quote code)
TRIGGER: (what properties of the input cause it)
FIX LOCATION: (file / function / line)
PROPOSED PATCH: (unified diff, minimal)

ASan report:
【粘贴 asan.txt】
```

---

## 5. 跑实验（≈ 1h30）

| 顺序 | Session | 新对话? | 预计 |
|---|---|---|---|
| 1 | Recall probe | 是 | 5 min |
| 2 | C0-1 | 是 | 10 min |
| 3 | C0-2（文件顺序打乱） | 是 | 10 min |
| 4 | C1-1 | 是 | 40 min |
| 5 | C2-1 | 是 | 25 min |
| 6（可选） | C2 patch → 跑 oracle | — | 15 min |

- 全部用**同一个模型**，记下名字+版本。关 memory / 自定义指令。
- 每个 session 结束立刻复制完整 transcript 到 `transcripts/`。
- 跑的时候顺手**截图**：C1 中途的 HYPOTHESIS 变化、C2 FINAL、oracle 结果。

---

## 6. 评分（30 min）— 对照第 1 节 ground truth

| 指标 | 规则 |
|---|---|
| **L_score** (C0/C1) | 2 = 真函数在 top-3 且机制描述对；1 = 提到真文件/函数但机制错或排名>3；0 = 没找到 |
| **true_bug_rank** | 真漏洞在候选里第几（没有填 none） |
| **false_candidates** | 候选总数 − 真漏洞（被你判为不成立的） |
| **read_impl** | Y = 引用了确实存在的具体代码行；N = 只凭函数名/通用经验 |
| **hallucinated_code_refs** | 引用了不存在/写错的代码的次数 |
| **R_score** (C2) | K1/K2/K3 命中数：3→2，1–2→1，0→0 |
| **fix_location_correct** | 修复位置与 ground truth 同函数且在相关检查处 |
| **patch_oracle** | 打 patch → PoC 不再 crash 且 `make check` 通过 = pass |
| **failure_mode** | 从下表选：`name-only`（只看名字不读实现）/ `ignored-evidence`（无视 ASan/返回内容）/ `fixation`（锁死在错误假设）/ `loop`（重复同一请求）/ `hallucination` / `refusal` / `none` |

C1 额外记：HYPOTHESIS 改了几次、改的原因是否来自读到的代码（这是“evidence-grounded”的证据）。

---

## 7. 结果写法（30 min）

### 7.1 主表（直接贴进报告）
| Step | Manual (Stage 1, GT) | C0 one-shot | C1 tool-mediated | C2 runtime evidence |
|---|---|---|---|---|
| Target understanding | 【Stage 1 记录】 | – | 【读了哪些文件、顺序】 | – |
| Localization | 【GT 位置】 | L=_/_, rank _, FP _ | L=_, rank _, FP _ | – |
| Root cause | 【GT】 | – | – | R=_ |
| Fix / validation | oracle pass | – | – | fix _, oracle _ |
| Human interventions | – | 0 | _ | _ |
| Failure mode | – | _ | _ | _ |

### 7.2 Findings 模板（挑 3–4 条成立的写）
1. Without tool access (C0), the model 【did / did not】 localize the bug; 【N】 false candidates, mostly 【pattern】.
2. With tool-mediated access (C1), the model 【read X files】 and revised its hypothesis 【N】 times; revisions 【were / were not】 grounded in code it read.
3. Given runtime evidence (C2), root-cause explanation scored 【R】/2; 【the patch passed / failed】 the oracle.
4. Observed failure mode: 【...】, suggesting 【...】 for Stage 3 (bounded agent design).
5. Recall probe: 【...】 → 【caveat】.

### 7.3 Limitations
直接用之前那段英文（analyst contamination → 已改为 GT 评分；operator bias → 固定 prompt + 干预规则；model contamination → recall probe 结果；n 小 → qualitative case study）。

---

## 8. 视频素材（20 min，不录）

90 秒提纲：
- **0–15s** Target：libcoap，CoAP 解析里的已知内存漏洞；Stage 1 人工分析作 ground truth。
- **15–35s** 怎么用 AI：同一模型、三种信息条件 C0/C1/C2，固定 prompt，人只按规则转发。
- **35–65s** 结果：放主表截图，讲 L/R 分数和一个 C1 假设修正的截图。
- **65–90s** 发现：AI 在哪步有用、典型失败模式、对 Stage 3 的启示（bounded tools + runtime verifier）。

需要截图：环境、C1 HYPOTHESIS 变化、C2 FINAL、oracle 结果、主表。
