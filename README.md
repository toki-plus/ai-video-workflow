# AI Video Workflow

[简体中文](./README.md) | [English](./README_en.md)

用于验证多模型协同的视频生成工作流原型。

项目将提示词生成、文生图、图生视频、文生音乐和媒体合成串联在一个桌面应用中，重点探索不同 AI 服务之间的任务编排、状态管理与人工选择点。

## 项目背景

生成式视频通常依赖多个模型和供应商：一个模型负责理解创意，一个模型生成图片，另一个模型生成视频或音乐。手工在多个平台之间传递提示词和文件，会增加等待、版本管理和失败重试成本。

AI Video Workflow 将这些步骤组织为一条可视化流水线，并允许用户在关键阶段预览和选择结果。

## 主要能力

- **AI 提示词生成**：内置基于豆包（Doubao）大模型的提示词生成器，提供多种预设主题与场景组合，一键产出整套图片、音乐提示词以及标题与标签草稿（发布前需人工确认）
- **文生图**：调用 LibLibAI 平台完成文生图任务，支持丰富的 Checkpoint、LoRA 模型与采样参数，可多次生成并对比候选结果
- **图生视频**：调用火山引擎即梦（Jimeng）I2V 模型，将选定的静态图片转换为平滑自然的动态视频
- **文生音乐**：接入即梦音乐模型，通过文本描述风格、情绪与乐器生成定制背景音乐
- **异步任务编排**：轮询各服务的异步任务状态、处理结果文件与失败边界，管理候选图片、视频和音频的多个版本
- **媒体合成与人工选择点**：使用 FFmpeg 将生成的视频与音乐合成为最终输出；提示词确认、图片选片、最终审核等关键节点均保留人工选择，界面支持在候选图片间前后翻页对比
- **三阶段桌面界面**：将创作过程分为"文生图 → 图生视频 → 文生音乐与合成"三个阶段，在 PyQt5 界面中集中配置参数、实时预览媒体、管理任务状态，并可一键重置流程

## 📸 软件截图

<p align="center">
  <img src="./assets/cover_demo_video.gif" alt="生成示例：最终视频" width="600"/>
  <br>
  <em>端到端生成示例：从提示词到带配乐的最终视频（动图演示）。</em>
</p>
<p align="center">
  <img src="./assets/cover_software01.png" alt="软件主界面：提示词生成" width="800"/>
  <br>
  <em>软件主界面：提示词生成部分。</em>
</p>
<p align="center">
  <img src="./assets/cover_software02.png" alt="软件主界面：图像参数" width="800"/>
  <br>
  <em>软件主界面：图像参数部分。</em>
</p>
<p align="center">
  <img src="./assets/cover_demo_picture.png" alt="生成示例：候选图像" width="390"/>
  <br>
  <em>生成示例：进入图生视频前的候选图像。</em>
</p>

## 工作流

```text
Creative brief
    -> Prompt generation
    -> Human review
    -> Text-to-image
    -> Image selection
    -> Image-to-video
    -> Music generation
    -> Media composition
    -> Final review
```

## 技术设计

- `LiblibClient`：文生图任务提交与状态查询
- `JimengI2VClient`：图生视频服务适配
- `JimengMusicClient`：音乐生成服务适配
- `AIGenerationPipeline`：跨服务工作流编排，统一处理异步轮询、超时与失败恢复
- `PromptGenerationStrategy`：可扩展提示词策略，预设主题与场景以策略形式注册
- `MainWindow`：参数、预览和任务状态管理

主要技术：Python、PyQt5、Volcengine SDK、LibLibAI API、FFmpeg/媒体处理库。

## 快速开始

### 环境要求

- Python 3.8+
- FFmpeg（需加入 `PATH`，可用 `ffmpeg -version` 验证）
- 对应模型服务的有效 API 凭据：豆包 API Key（提示词生成）、LibLibAI Access/Secret Key（文生图）、火山引擎 Access/Secret Key（图生视频与文生音乐）

### 安装与启动

1. 克隆仓库并创建虚拟环境：

```bash
git clone https://github.com/toki-plus/ai-video-workflow.git
cd ai-video-workflow
python -m venv venv
# Windows: venv\Scripts\activate
# macOS/Linux: source venv/bin/activate
```

2. 安装依赖：

```bash
pip install -r requirements.txt
```

3. 配置凭据（建议通过环境变量，程序自动读取；也可启动后在 "API 密钥" 标签页中填写）：

```text
DOUBAO_API_KEY
LIBLIB_AK
LIBLIB_SK
JIMENG_AK
JIMENG_SK
```

4. 运行程序：

```bash
python ai-video-workflow.py
```

典型使用路径：选择主题与场景生成提示词并人工确认 → 文生图并翻页选出满意的候选图 → 图生视频 → 生成配乐并合成最终视频（产物保存在 `output` 目录，可随时一键重置开始新一轮）。

## 使用边界

- 不同供应商的接口、配额和模型行为可能发生变化。
- 生成结果应经过人工审核，并遵守素材版权与模型服务条款。
- API 凭据只能保存在安全的本地环境中，不要提交到仓库。
- 当前实现以原型验证为主，尚未建立完整的自动化测试与 CI。

## 项目价值

本项目展示的核心不是单次生成效果，而是多模型服务的抽象、异步任务编排、失败边界和人工确认点设计：每个供应商被封装为可替换的客户端，提示词策略可扩展，关键阶段的产出始终由人选择后才进入下一步。

## 📂 更多项目

- [video-mover](https://github.com/toki-plus/video-mover) — 多平台内容分发自动化流水线：素材处理、文案生成、定时调度与多平台适配
- [ai-highlight-clip](https://github.com/toki-plus/ai-highlight-clip) — 长视频智能初筛：Whisper 转写 + LLM 评分 + 人工终审，分钟级定位高光片段
- [ai-ttv-workflow](https://github.com/toki-plus/ai-ttv-workflow) — 文案到短视频的桌面工作流，关键节点保留人工确认
- [ai-mixed-cut](https://github.com/toki-plus/ai-mixed-cut) — 素材库结构化与脚本重组的视频再创作工作流
- [ai-trader-for-mt4](https://github.com/toki-plus/ai-trader-for-mt4) — LLM×MT4 受控执行框架：工具约束、风控规则、状态管理与异步桥接
- [ai-trader-for-mt5](https://github.com/toki-plus/ai-trader-for-mt5) — 面向 MT5 的 AI 交易助手与 EA 工程化框架
- [auto-usps-tracker](https://github.com/toki-plus/auto-usps-tracker) — 跨境电商批量物流追踪与 Excel 报告自动化
- [AB-Video-Deduplicator](https://github.com/toki-plus/AB-Video-Deduplicator) — 基于高帧率抽帧混合的视频再创作实验工具
- [netease-downloader](https://github.com/toki-plus/netease-downloader) — 网易云音乐下载桌面应用：扫码登录、下载队列、ID3 元数据写入

## License

See [LICENSE](./LICENSE).
