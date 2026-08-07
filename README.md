# AI Video Workflow

用于验证多模型协同的视频生成工作流原型。

项目将提示词生成、文生图、图生视频、文生音乐和媒体合成串联在一个桌面应用中，重点探索不同 AI 服务之间的任务编排、状态管理与人工选择点。

## 项目背景

生成式视频通常依赖多个模型和供应商：一个模型负责理解创意，一个模型生成图片，另一个模型生成视频或音乐。手工在多个平台之间传递提示词和文件，会增加等待、版本管理和失败重试成本。

AI Video Workflow 将这些步骤组织为一条可视化流水线，并允许用户在关键阶段预览和选择结果。

## 主要能力

- 使用大模型生成和调整视觉提示词
- 调用 LibLibAI 完成文生图任务
- 调用火山引擎相关服务完成图生视频与音乐生成
- 轮询异步任务状态并处理结果文件
- 管理候选图片、视频和音频版本
- 将生成的视频和音乐合成为最终输出
- 在 PyQt5 界面中配置参数、预览结果和重启流程

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
- `AIGenerationPipeline`：跨服务工作流编排
- `PromptGenerationStrategy`：可扩展提示词策略
- `MainWindow`：参数、预览和任务状态管理

主要技术：Python、PyQt5、Volcengine SDK、LibLibAI API、FFmpeg/媒体处理库。

## 快速开始

### 环境要求

- Python 3.8+
- FFmpeg（需加入 `PATH`）
- 对应模型服务的有效 API 凭据

```bash
git clone https://github.com/toki-plus/ai-video-workflow.git
cd ai-video-workflow
python -m venv venv
```

激活虚拟环境后：

```bash
pip install -r requirements.txt
python ai-video-workflow.py
```

建议通过环境变量提供凭据：

```text
DOUBAO_API_KEY
LIBLIB_AK
LIBLIB_SK
JIMENG_AK
JIMENG_SK
```

## 使用边界

- 不同供应商的接口、配额和模型行为可能发生变化。
- 生成结果应经过人工审核，并遵守素材版权与模型服务条款。
- API 凭据只能保存在安全的本地环境中。
- 当前实现以原型验证为主，尚未建立完整的自动化测试与 CI。

## 项目价值

本项目展示的核心不是单次生成效果，而是多模型服务的抽象、异步任务编排、失败边界和人工确认点设计。

## License

See [LICENSE](./LICENSE).
