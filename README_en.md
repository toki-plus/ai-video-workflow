# AI Video Workflow

A workflow prototype for coordinating multiple generative-AI services in video production.

The project connects prompt generation, text-to-image, image-to-video, text-to-music, and media composition in one desktop application. Its focus is cross-provider orchestration, state management, and human review points.

## Context

Generative-video workflows often depend on several models and vendors: one interprets the brief, another creates images, and others generate video or music. Moving prompts and files manually between services increases waiting time, version-management overhead, and retry effort.

AI Video Workflow organizes the steps into a visual pipeline and allows users to review and select outputs at key stages.

## Capabilities

- Generate and refine visual prompts with an LLM
- Submit text-to-image jobs to LibLibAI
- Use Volcengine-related services for image-to-video and music generation
- Poll asynchronous task status and collect output files
- Manage candidate image, video, and audio versions
- Compose generated video and music into a final output
- Configure parameters, preview results, and restart workflows in a PyQt5 interface

## Workflow

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

## Technical Design

- `LiblibClient`: text-to-image submission and status polling
- `JimengI2VClient`: image-to-video provider adapter
- `JimengMusicClient`: music-generation provider adapter
- `AIGenerationPipeline`: cross-service orchestration
- `PromptGenerationStrategy`: extensible prompt strategies
- `MainWindow`: parameter, preview, and task-state management

Core technologies: Python, PyQt5, the Volcengine SDK, LibLibAI APIs, and FFmpeg/media-processing libraries.

## Quick Start

### Requirements

- Python 3.8+
- FFmpeg available on `PATH`
- Valid credentials for the configured model providers

```bash
git clone https://github.com/toki-plus/ai-video-workflow.git
cd ai-video-workflow
python -m venv venv
```

After activating the virtual environment:

```bash
pip install -r requirements.txt
python ai-video-workflow.py
```

Environment variables are recommended for credentials:

```text
DOUBAO_API_KEY
LIBLIB_AK
LIBLIB_SK
JIMENG_AK
JIMENG_SK
```

## Limitations and Responsible Use

- Provider APIs, quotas, and model behavior may change.
- Generated outputs require human review and must comply with copyright and provider terms.
- API credentials must remain in secure local configuration.
- The current implementation is a workflow prototype and does not yet include comprehensive automated tests or CI.

## What This Project Demonstrates

The core value is not a single generated asset. It is the abstraction of multiple model providers, asynchronous job orchestration, failure boundaries, and human approval points.

## License

See [LICENSE](./LICENSE).
