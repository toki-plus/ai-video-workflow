# AI Video Workflow: 全自动 AI 原生视频生成工作流

[简体中文](./README.md) | [English](./README_en.md)

[![GitHub stars](https://img.shields.io/github/stars/toki-plus/ai-video-workflow?style=social)](https://github.com/toki-plus/ai-video-workflow/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/toki-plus/ai-video-workflow?style=social)](https://github.com/toki-plus/ai-video-workflow/network/members)
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/toki-plus/ai-video-workflow/pulls)

**`AI Video Workflow` 是一款免费、开源的桌面应用程序，它将多个顶尖的AI模型（文生图、图生视频、文生音乐）串联成一个全自动的AI原生视频创作流水线。**

你是否想创作引人注目的AI短视频，却被繁琐的平台切换、复杂的参数调整和枯竭的创作灵感所困扰？本项目旨在将AI视频创作的整个过程简化为几次点击，让任何人都能轻松生成具有独特视觉风格和定制化配乐的短视频。

<p align="center">
  <a href="https://www.bilibili.com" target="_blank">
    <img src="" alt="点击观看B站演示视频（暂未录制）" width="800"/>
  </a>
  <br>
  <em>(点击图片跳转到 B 站观看高清演示视频)</em>
</p>

---

## ✨ 核心功能

这不仅是一个工具，更是一个完整的 AIGC 创作生态系统：

-   **🤖 全自动AI创作流水线**:
    -   **文生图 (Text-to-Image)**: 对接 **LibLibAI** 平台，支持丰富的 Checkpoint、LoRA 模型和参数，将您的想法变为精美图像。
    -   **图生视频 (Image-to-Video)**: 调用火山引擎 **即梦（Jimeng）I2V** 模型，为静态图片赋予生命，生成平滑自然的动态视频。
    -   **文生音乐 (Text-to-Music)**: 接入火山引擎 **即梦（Jimeng）音乐** 模型，通过文本描述（如风格、情绪、乐器）即可生成独一无二的背景音乐。
    -   **自动合成 (Automatic Merging)**: 使用强大的 **FFmpeg** 引擎，将生成的视频画面与背景音乐无缝合成为最终的成品视频。

-   **💡 AI驱动的灵感引擎**:
    -   内置基于 **豆包（Doubao）大模型** 的提示词生成器。
    -   提供“美女”、“Labubu”等多种预设主题，只需勾选想要的风格（如“沙滩”、“健身房”或“糖果系”、“魔法系”），即可一键生成全套专业的图片、音乐提示词和爆款标题、标签。

-   **🎨 直观的图形化界面 (GUI)**:
    -   **三步式工作流**: 清晰地将创作过程分为“文生图 → 图生视频 → 文生音乐与合成”三个阶段，每一步的进展和结果都一目了然。
    -   **集中式参数管理**: 在统一的界面中配置所有AI模型的参数，无需在多个网页或应用间切换。
    -   **实时媒体预览**: 生成的图片和视频会直接在界面中展示和播放，方便您即时评估效果。
    -   **历史记录与导航**: 支持在多张生成的图片之间轻松切换，方便您选择最满意的一张进入下一步。

## 📸 软件截图

<p align="center">
  <img src="./assets/cover_software01.png" alt="软件主界面" width="800"/>
  <br>
  <em>软件主界面：提示词生成部分。</em>
</p>
<p align="center">
  <img src="./assets/cover_software02.png" alt="软件主界面" width="800"/>
  <br>
  <em>软件主界面：图像参数部分。</em>
</p>

<table align="center">
  <tr>
    <td align="center" valign="top">
      <img src="./assets/cover_demo_picture.png" alt="生成示例：生成图像" width="390"/>
      <br />
      <em>生成示例：生成图像。</em>
    </td>
    <td align="center" valign="top">
      <img src="./assets/cover_demo_video.gif" alt="生成示例：最终视频" width="390"/>
      <br />
      <em>生成示例：最终视频。</em>
    </td>
  </tr>
</table>

## 🚀 快速开始

### 系统要求

1.  **Python**: 3.8 或更高版本。
2.  **FFmpeg**: **必须**安装 FFmpeg 并将其添加到系统环境变量中。
    -   请访问 [FFmpeg 官网](https://ffmpeg.org/download.html) 查看安装教程。
    -   检查是否安装成功：打开终端或命令提示符，输入 `ffmpeg -version`。
3.  **API Keys**:
    -   **豆包（Doubao） API Key**: 用于提示词生成。
    -   **LibLibAI Access Key & Secret Key**: 用于文生图。
    -   **火山引擎（即梦）Access Key & Secret Key**: 用于图生视频和文生音乐。

### 安装与启动

1.  **克隆本仓库：**
    ```bash
    git clone https://github.com/toki-plus/ai-video-workflow.git
    cd ai-video-workflow
    ```

2.  **创建并激活虚拟环境 (推荐)：**
    ```bash
    python -m venv venv
    # Windows 系统
    venv\Scripts\activate
    # macOS/Linux 系统
    source venv/bin/activate
    ```

3.  **安装依赖库：**
    ```bash
    pip install -r requirements.txt
    ```

4.  **配置 API Keys:**
    -   **强烈建议**通过设置系统环境变量来配置密钥，程序会自动读取：
        - `DOUBAO_API_KEY`
        - `LIBLIB_AK`, `LIBLIB_SK`
        - `JIMENG_AK`, `JIMENG_SK`
    -   或者，您也可以在软件启动后，在 "API 密钥" 标签页中手动输入。

5.  **运行程序：**
    ```bash
    python ai_video_workflow.py
    ```

## 📖 使用指南

1.  **第一步：配置与准备**
    -   启动软件，在左侧的 "API 密钥" 标签页中确认所有密钥已填写正确，点击“保存当前参数”应用。
    -   切换到 "提示词生成" 标签页，选择一个您感兴趣的主题（如“美女”），勾选几个场景，然后点击“生成提示词”。
    -   在下方生成的表格中，选择最喜欢的一行，点击“应用选中行提示词”。

2.  **第二步：文生图**
    -   参数会自动填充到“图像参数”和“音视频参数”标签页，您也可以手动修改。
    -   在右侧工作流面板，点击“开始生成图片”。等待片刻，生成的图片将显示在预览区。
    -   您可以多次生成，并通过“上一张”/“下一张”按钮选择最满意的图片。

3.  **第三步：图生视频**
    -   确认已选中满意的图片后，点击“生成视频”。程序会将该图片发送到AI模型进行处理。
    -   处理完成后，生成的无声视频会自动在预览区循环播放。

4.  **第四步：文生音乐与合成**
    -   点击“合成最终视频”。程序将使用“音视频参数”中的音乐提示词生成配乐，并与视频合并。
    -   任务完成后，最终的带配乐视频将在预览区播放，并保存在 `output` 文件夹中。

5.  **完成！**
    -   点击“全部重来”可以清空当前状态，开始一次全新的创作。

---

<p align="center">
  <strong>技术交流，请添加：</strong>
</p>
<table align="center">
  <tr>
    <td align="center">
      <img src="./assets/wechat.png" alt="微信二维码" width="200"/>
      <br />
      <sub><b>个人微信</b></sub>
      <br />
      <sub>微信号: toki-plus (请备注“GitHub 定制”)</sub>
    </td>
    <td align="center">
      <img src="./assets/gzh.png" alt="公众号二维码" width="200"/>
      <br />
      <sub><b>公众号</b></sub>
      <br />
      <sub>获取最新技术分享与项目更新</sub>
    </td>
  </tr>
</table>

## 📂 我的其他开源项目

-   **[AI Mixed-Cut](https://github.com/toki-plus/ai-mixed-cut)**: 一款颠覆性的AI内容生产工具，通过“解构-重构”模式将爆款视频解构成创作素材库，并全自动生成全新原创视频。
-   **[AI Highlight Clip](https://github.com/toki-plus/ai-highlight-clip)**: 一款AI驱动的智能剪辑工具，能够全自动地从长视频中分析、发现并剪辑出多个“高光时刻”短视频，并自动生成爆款标题。
-   **[AI TTV Workflow](https://github.com/toki-plus/ai-ttv-workflow)**: 一款AI驱动的文本转视频工具，能将任意文案自动转化为带有配音、字幕和封面的短视频，支持AI文案提取、二创和翻译。
-   **[Video Mover](https://github.com/toki-plus/video-mover)**: 一个强大的、全自动化的内容创作流水线工具。它可以自动监听、下载指定的博主发布的视频，进行深度、多维度的视频去重处理，并利用AI大模型生成爆款标题，最终自动发布到不同平台。
-   **[AB Video Deduplicator](https://github.com/toki-plus/AB-Video-Deduplicator)**: 通过创新的“高帧率抽帧混合”技术，从根本上重构视频数据指纹，以规避主流短视频平台的原创度检测和查重机制。

## 🤝 参与贡献

欢迎任何形式的贡献！如果你有新的功能点子、发现了Bug，或者有任何改进建议，请：
-   提交一个 [Issue](https://github.com/toki-plus/ai-video-workflow/issues) 进行讨论。
-   Fork 本仓库并提交 [Pull Request](https://github.com/toki-plus/ai-video-workflow/pulls)。

如果这个项目对你有帮助，请不吝点亮一颗 ⭐！

## 📜 开源协议

本项目基于 MIT 协议开源。详情请见 [LICENSE](LICENSE) 文件。
