# Polar-LAC 选择密文攻击（NGCC 参考实现）

对 NGCC 提交包 **Polar-LAC KEM** 参考实现的本地端到端选择密文攻击复现。利用 FO 重加密里拒绝采样循环的轮数泄漏（plaintext-checking oracle，PCO），结合不完全 NTT 的**块隔离**，逐块恢复私钥 $\hat s$。

被攻击目标是 **自包含的参考实现**（纯 C，clang/gcc 即可编译，无外部依赖），随仓库一起 vendored：

| 目录 | 参数集 | q | K | c2 量化 |
|---|---|---|---|---|
| `ref_light/` | POLARLAC-Light | 257 | 2 | 3-bit |
| `ref128/` | POLARLAC kem-30 | 257 | 2 | 4-bit |

## 仓库结构

保留两种 oracle 各一个全密钥恢复实现——一个理论、一个实际：

```
├── pco_keyrecovery.c    # 理论 oracle：块隔离 PCO，决策用 FO 拒绝采样轮数 J
│                        #   两阶段消歧，257²×128×2，D_C2_BITS 自适应（Light 3-bit / kem-30 4-bit）
├── timing_fullkey.c     # 实际 oracle：真实墙钟计时端到端，多核并行恢复全部 256 块
│                        #   决策只用 decaps 墙钟时间（差分 min-of-R vs J=0 参考）
├── ref_light/           # 被攻击目标：POLARLAC-Light 参考实现（自包含）
├── ref128/              # 被攻击目标：POLARLAC kem-30 参考实现（自包含）
├── run_pco.sh           # 一键运行：理论 oracle（J 轮数）全密钥恢复
├── run_timing.sh        # 一键运行：实际 oracle（真实计时）全密钥恢复
└── build.sh             # 一键构建（对两个目标交叉编译各攻击）
```

## 构建

```bash
bash build.sh            # 构建全部攻击 × 全部适用目标
bash build.sh light      # 仅 ref_light
bash build.sh 128        # 仅 ref128
```

产物进 `build/`：`pco_keyrecovery_{light,128}`、`timing_fullkey_{light,128}`。

默认后端开关与 NGCC 提交一致：`BIT_USE_SHAKE=0`（SM3）、`RL_KEM_USE_CONJ_NTT_REJECTION=0`。

## 运行

两个一键脚本（自动按需构建），各对应一种 oracle；运行时实时打印进度、ETA、累计查询数：

```bash
# 理论 oracle（精确 J 轮数）：快、确定性，约 5 分钟（降频下 ~17 分钟）
bash run_pco.sh              # ref_light
bash run_pco.sh 128          # ref128

# 实际 oracle（真实墙钟计时）：多核并行，6 核约 1 小时
bash run_timing.sh           # ref_light，默认 6 线程
bash run_timing.sh 128       # ref128
NT=12 bash run_timing.sh     # 自定义并行线程数
```

或直接调用二进制：

```bash
./build/pco_keyrecovery_light           # 理论：全密钥，J-oracle 两阶段，末尾用新鲜密文验证
./build/timing_fullkey_light [nthreads] # 实际：全密钥，真实计时，多核并行
```

> 实际计时攻击对 CPU 频率抖动敏感；为稳定测量，运行前建议固定主频（关闭 turbo、performance governor）。
>
> 攻击纪律：所有 accept/reject 决策只依赖拒绝采样轮数 J（`pco_keyrecovery`）或 decaps 墙钟时间（`timing_fullkey`）；`compute_J` 只对攻击者选定的 $m$ 在公开 pk 上离线计算，绝不作用于解密出的 $m'$；真实私钥仅用于最终评分，不参与任何决策。演示密钥均为本地进程内生成。

## 泄漏与修复

**根因**：`kem_dec` 的 FO 重加密里，`sample_screened_poly` 对 r、e1 的谱界筛选是拒绝循环，轮数 $J$ 由 `seed = XOF(m'\|pk)` 唯一决定。pk 公开，故攻击者可对任意候选明文离线预计算其精确轮数——$J$ 因此是一个明文检查 oracle（PCO）：解封装恢复出的 $m'$ 是否等于攻击者选定的 $m^*$，可由 $J(m')\overset{?}{=}J(m^*)$ 判定，无需任何明文访问。隐式拒绝（`ct_verify`/`ct_cmov`）只消除了成功/失败的**路径**差异，消除不了这条**数据路径**上随 $m'$ 变化的耗时。

配合不完全 NTT 的块隔离（见 `pco_keyrecovery.c` 顶部注释），每块只剩两个未知量，$257^2$ 穷举 + 两阶段消歧即逐块恢复 $\hat s$。$J$ 既可用精确轮数读出（`pco_keyrecovery`），也可用一次解封装的墙钟时间读出（`timing_fullkey`，$\text{decaps} = a + b\cdot J$）。

**修复建议**：①**常数轮数采样**——`sample_screened_poly*` 固定消耗 $C$ 个候选（如 $C=8/12$，覆盖 $P(\text{不足})<2^{-40}$），不足则整种子重派生或固定填充，分布不变；②更彻底：谱界筛选改为**无拒绝**构造（从固定数量 XOF 输出确定性映射到谱界内多项式）；③修复后 KAT 应保持不变（候选流不变 ⇒ 密文不变）。

## 授权说明

本仓库为授权安全研究产物，针对公开开源代码库自身的缺陷，演示密钥均为本地进程内生成。请勿用于对未授权目标发起攻击。
