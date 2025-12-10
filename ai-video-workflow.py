import os
import av
import sys
import hmac
import time
import uuid
import json
import base64
import shutil
import datetime
import requests
import threading
import subprocess
import numpy as np
from urllib.parse import quote
from hashlib import sha1, sha256
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from volcenginesdkarkruntime import Ark
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QTextEdit, QLineEdit, QFileDialog,
                             QScrollArea, QFrame, QFormLayout, QSpinBox, QStyledItemDelegate,
                             QDoubleSpinBox, QTabWidget, QMessageBox, QDesktopWidget, QComboBox,
                             QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
                             QGridLayout, QGroupBox)
from PyQt5.QtGui import QPixmap, QMovie, QIcon, QImage, QTextCursor, QTextOption, QDesktopServices
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QUrl, QTimer


STYLESHEET = """
QWidget { font-family: 'Segoe UI', 'Microsoft YaHei', 'Calibri'; font-size: 14px; color: #E0E0E0; selection-background-color: #1ABC9C; selection-color: #FFFFFF; }
QMainWindow, QDialog { background-color: #2C313C; }
QFrame { border: none; }
QTabWidget::pane { border: 1px solid #444B5A; border-top: none; background-color: #353B48; }
QTabBar::tab { background: #353B48; color: #B0B0B0; padding: 12px 25px; border: 1px solid #444B5A; border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; }
QTabBar::tab:selected { background: #4A5160; color: #FFFFFF; font-weight: bold; }
QTabBar::tab:hover { background: #424855; }
QPushButton { background-color: #4A5160; border: 1px solid #5A6170; padding: 8px 16px; border-radius: 5px; }
QPushButton:hover { background-color: #5A6170; border-color: #6A7180; }
QPushButton:pressed { background-color: #404652; }
QPushButton:disabled { background-color: #3A404D; color: #808080; border-color: #4A5170; }
QPushButton#PrimaryButton { background-color: #1ABC9C; color: #FFFFFF; font-weight: bold; border: none; }
QPushButton#PrimaryButton:hover { background-color: #1DCCAB; }
QPushButton#PrimaryButton:pressed { background-color: #16A085; }
QPushButton#RestartButton { background-color: #E67E22; color: #FFFFFF; font-weight: bold; border: none; }
QPushButton#RestartButton:hover { background-color: #F39C12; }
QPushButton#RestartButton:pressed { background-color: #D35400; }
QLineEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox { background-color: #3A404D; border: 1px solid #505869; padding: 6px; border-radius: 5px; color: #E0E0E0; }
QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus { border: 1px solid #1ABC9C; }
QComboBox { padding-right: 20px; }
QComboBox QAbstractItemView { background-color: #3A404D; border: 1px solid #5A6170; padding: 4px; selection-background-color: #1ABC9C; }
QTextEdit { font-family: 'Consolas', 'Courier New', monospace; }
QLabel { background-color: transparent; }
QLabel#TitleLabel { font-size: 24px; font-weight: bold; color: #FFFFFF; padding-bottom: 10px; }
QLabel#StepLabel { font-size: 18px; font-weight: bold; padding: 10px; background-color: #3A404D; border-radius: 5px; color: #A0A0A0; }
QLabel#StepLabel[active="true"] { background-color: #1ABC9C; color: white; }
QLabel#MediaPlaceholder { background-color: #3A404D; border: 2px dashed #505869; border-radius: 8px; color: #888; font-size: 20px; }
QScrollArea { border: none; background-color: #2C313C; }
QScrollBar:vertical { border: none; background: #353B48; width: 12px; margin: 0px 0px 0px 0px; }
QScrollBar::handle:vertical { background: #4A5160; min-height: 25px; border-radius: 6px; }
QScrollBar::handle:vertical:hover { background: #5A6170; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }
QScrollBar:horizontal { border: none; background: #353B48; height: 12px; margin: 0px 0px 0px 0px; }
QScrollBar::handle:horizontal { background: #4A5160; min-width: 25px; border-radius: 6px; }
QScrollBar::handle:horizontal:hover { background: #5A6170; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: none; }
QMenu { background-color: #3A404D; border: 1px solid #5A6170; padding: 5px; color: #E0E0E0; }
QMenu::item { padding: 5px 25px 5px 20px; border-radius: 4px; }
QMenu::item:selected { background-color: #1ABC9C; color: #FFFFFF; }
QMenu::separator { height: 1px; background: #5A6170; margin-left: 10px; margin-right: 5px; }
QTableWidget { background-color: #353B48; border: 1px solid #444B5A; gridline-color: #444B5A; outline: 0; }
QTableWidget::item { padding: 8px; border: none; border-bottom: 1px solid #444B5A; }
QTableWidget::item:alternate { background-color: #3A404D; }
QTableWidget::item:selected { background-color: #5A6170; }
QHeaderView { background-color: #4A5160; }
QHeaderView::section { background-color: #4A5160; color: #E0E0E0; padding: 8px; border: none; border-bottom: 2px solid #2C313C; font-weight: bold; }
QTableCornerButton::section { background-color: #4A5160; border: none; border-bottom: 2px solid #2C313C; }
QVideoWidget { background-color: black; }
QPushButton#LoraActionButton { font-size: 18px; font-weight: bold; padding: 4px; }
QGroupBox { color: #E0E0E0; border: 1px solid #444B5A; border-radius: 5px; margin-top: 10px; padding: 10px 5px 5px 5px; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; left: 10px; color: #1ABC9C; font-weight: bold; }
QMenuBar { background-color: #2C313C; color: #E0E0E0; padding-left: 5px; border-bottom: 1px solid #444B5A; }
QMenuBar::item { background-color: transparent; padding: 6px 12px; border-radius: 4px; }
QMenuBar::item:selected { background-color: #4A5160; }
QMenuBar::item:pressed { background-color: #1ABC9C; color: #FFFFFF; }
"""
class LiblibClient:
    BASE_URL = "https://openapi.liblibai.cloud"
    TEXT2IMG_ENDPOINT = "/api/generate/webui/text2img"
    STATUS_ENDPOINT = "/api/generate/webui/status"
    DEFAULT_TEMPLATE_UUID = 'e10adc3949ba59abbe56e057f20f883e'
    def __init__(self, access_key: str, secret_key: str):
        if not access_key or not secret_key:
            raise ValueError("LibLib 的 AccessKey 和 SecretKey 不能为空。")
        self.access_key = access_key
        self.secret_key = secret_key
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
    def _make_sign(self, uri: str) -> Dict[str, str]:
        timestamp = str(int(time.time() * 1000))
        signature_nonce = str(uuid.uuid4())
        content = f"{uri}&{timestamp}&{signature_nonce}"
        digest = hmac.new(self.secret_key.encode('utf-8'), content.encode('utf-8'), sha1).digest()
        sign = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')
        return {"Signature": sign, "Timestamp": timestamp, "SignatureNonce": signature_nonce}
    def _make_request(self, method: str, endpoint: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        full_url = self.BASE_URL + endpoint
        auth_params = self._make_sign(endpoint)
        query_params = {"AccessKey": self.access_key, **auth_params}
        try:
            response = self.session.request(method, full_url, params=query_params, json=payload)
            response.raise_for_status()
            response_json = response.json()
            if response_json.get("code") != 0:
                error_msg = response_json.get('msg', '未知错误')
                raise ValueError(f"LibLib API 请求失败 - Code: {response_json.get('code', 'N/A')}, Message: {error_msg}")
            return response_json
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"LibLib HTTP请求错误: {e}")
        except json.JSONDecodeError:
            raise ValueError(f"无法解析LibLib服务器响应: {response.text}")
    def submit_text_to_image_task(self, params: Dict[str, Any]) -> str:
        generate_params = params.copy()
        template_uuid = generate_params.pop('template_uuid', self.DEFAULT_TEMPLATE_UUID)
        generate_params = {k: v for k, v in generate_params.items() if v is not None}
        payload = {"templateUuid": template_uuid, "generateParams": generate_params}
        response = self._make_request("POST", self.TEXT2IMG_ENDPOINT, payload)
        generate_uuid = response.get('data', {}).get('generateUuid')
        if not generate_uuid:
            raise ValueError(f"提交LibLib任务失败，未能从响应中获取 generateUuid。响应: {response}")
        return generate_uuid
    def query_task_status(self, generate_uuid: str) -> Dict[str, Any]:
        payload = {"generateUuid": generate_uuid}
        return self._make_request("POST", self.STATUS_ENDPOINT, payload)
class VolcengineAuth:
    def __init__(self, access_key: str, secret_key: str, region: str, service: str):
        if not all([access_key, secret_key, region, service]):
            raise ValueError("火山引擎认证: access_key, secret_key, region, 和 service 都不能为空。")
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = service
    def _hmac_sha256(self, key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode('utf-8'), sha256).digest()
    def _hash_sha256(self, content: str) -> str:
        return sha256(content.encode('utf-8')).hexdigest()
    def _get_signing_key(self, date_stamp: str) -> bytes:
        k_date = self._hmac_sha256(self.secret_key.encode('utf-8'), date_stamp)
        k_region = self._hmac_sha256(k_date, self.region)
        k_service = self._hmac_sha256(k_region, self.service)
        k_signing = self._hmac_sha256(k_service, 'request')
        return k_signing
    def get_auth_headers(self, http_method: str, host: str, canonical_uri: str,
                         query_params: Dict[str, str], request_body_str: str,
                         content_type: str = 'application/json') -> Dict[str, str]:
        t = datetime.datetime.utcnow()
        current_date_utc = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')
        payload_hash = self._hash_sha256(request_body_str)
        sorted_query_params = sorted(query_params.items())
        canonical_querystring = "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in sorted_query_params)
        signed_headers_list = sorted(['host', 'content-type', 'x-date', 'x-content-sha256'])
        signed_headers_str_for_auth = ';'.join(signed_headers_list)
        canonical_headers_map = {
            'host': host,
            'content-type': content_type,
            'x-date': current_date_utc,
            'x-content-sha256': payload_hash
        }
        _canonical_headers_lines = [f"{k.lower()}:{str(canonical_headers_map[k]).strip()}" for k in signed_headers_list]
        canonical_headers_for_req_no_trailing_newline = "\n".join(_canonical_headers_lines)
        canonical_request = (
            f'{http_method.upper()}\n'
            f'{canonical_uri}\n'
            f'{canonical_querystring}\n'
            f'{canonical_headers_for_req_no_trailing_newline}\n'
            f'\n'
            f'{signed_headers_str_for_auth}\n'
            f'{payload_hash}'
        )
        algorithm = 'HMAC-SHA256'
        credential_scope = f'{datestamp}/{self.region}/{self.service}/request'
        hashed_canonical_request = self._hash_sha256(canonical_request)
        string_to_sign = (
            f'{algorithm}\n'
            f'{current_date_utc}\n'
            f'{credential_scope}\n'
            f'{hashed_canonical_request}'
        )
        signing_key = self._get_signing_key(datestamp)
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), sha256).hexdigest()
        authorization_header = (
            f'{algorithm} Credential={self.access_key}/{credential_scope}, '
            f'SignedHeaders={signed_headers_str_for_auth}, Signature={signature}'
        )
        return {
            'X-Date': current_date_utc,
            'X-Content-Sha256': payload_hash,
            'Authorization': authorization_header,
            'Content-Type': content_type
        }
class JimengI2VClient:
    _HOST = 'visual.volcengineapi.com'
    _REGION = 'cn-north-1'
    _SERVICE = 'cv'
    _API_VERSION = '2022-08-31'
    _CANONICAL_URI = '/'
    _HTTP_METHOD = 'POST'
    def __init__(self, access_key: str, secret_key: str):
        if not access_key or not secret_key:
            raise ValueError("即梦图生视频的 AccessKey 和 SecretKey 不能为空。")
        self.auth_helper = VolcengineAuth(access_key, secret_key, self._REGION, self._SERVICE)
        self.endpoint = f'https://{self._HOST}'
    def _make_request(self, action: str, body_params: Dict[str, Any]) -> Dict[str, Any]:
        query_params = {'Action': action, 'Version': self._API_VERSION}
        request_body_str = json.dumps(body_params)
        auth_headers_dict = self.auth_helper.get_auth_headers(
            http_method=self._HTTP_METHOD,
            host=self._HOST,
            canonical_uri=self._CANONICAL_URI,
            query_params=query_params,
            request_body_str=request_body_str
        )
        headers = {
            'Content-Type': auth_headers_dict['Content-Type'],
            'X-Date': auth_headers_dict['X-Date'],
            'X-Content-Sha256': auth_headers_dict['X-Content-Sha256'],
            'Authorization': auth_headers_dict['Authorization']
        }
        sorted_query_params_list = sorted(query_params.items())
        url_query_string = "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in sorted_query_params_list)
        try:
            response = requests.post(f'{self.endpoint}?{url_query_string}', headers=headers, data=request_body_str.encode('utf-8'))
            response.raise_for_status()
            response_json = response.json()
            if 'ResponseMetadata' in response_json and 'Error' in response_json['ResponseMetadata']:
                error_info = response_json['ResponseMetadata']['Error']
                raise ValueError(f"即梦图生视频 API 错误: Code={error_info.get('Code')}, Message={error_info.get('Message')}")
            return response_json
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"即梦图生视频 HTTP请求失败: {e}")
        except json.JSONDecodeError:
            raise ValueError(f"无法解析即梦图生视频服务器响应: {response.text}")
    def submit_video_generation_task(self, image_url: str, **kwargs: Any) -> str:
        body_params = {
            "req_key": "jimeng_vgfm_i2v_l20",
            "image_urls": [image_url],
            "aspect_ratio": kwargs.get('aspect_ratio', '9:16'),
            "seed": kwargs.get('seed', -1),
            "prompt": ""
        }
        response = self._make_request(action='CVSync2AsyncSubmitTask', body_params=body_params)
        task_id = response.get('data', {}).get('task_id')
        if not task_id:
            raise ValueError(f"提交即梦图生视频任务失败，未能从响应中获取 task_id。响应: {response}")
        return task_id
    def query_task_status(self, task_id: str) -> Dict[str, Any]:
        body_params = {"req_key": "jimeng_vgfm_i2v_l20", "task_id": task_id}
        return self._make_request(action='CVSync2AsyncGetResult', body_params=body_params)
class JimengMusicClient:
    _HOST = "open.volcengineapi.com"
    _SERVICE = "imagination"
    _API_VERSION = "2024-08-12"
    _BASE_URL = f"https://{_HOST}"
    _CANONICAL_URI = "/"
    def __init__(self, access_key: str, secret_key: str, region: str = "cn-beijing"):
        if not access_key or not secret_key:
            raise ValueError("即梦音乐的 AccessKey 和 SecretKey 不能为空。")
        self.auth_helper = VolcengineAuth(access_key, secret_key, region, self._SERVICE)
    def _request(self, method: str, action: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        query_params = {'Action': action, 'Version': self._API_VERSION}
        body_str = json.dumps(body) if body else ""
        auth_headers_dict = self.auth_helper.get_auth_headers(
            http_method=method.upper(),
            host=self._HOST,
            canonical_uri=self._CANONICAL_URI,
            query_params=query_params,
            request_body_str=body_str
        )
        headers = {
            'Host': self._HOST,
            'Content-Type': auth_headers_dict['Content-Type'],
            'X-Date': auth_headers_dict['X-Date'],
            'X-Content-Sha256': auth_headers_dict['X-Content-Sha256'],
            'Authorization': auth_headers_dict['Authorization']
        }
        sorted_query_params_list = sorted(query_params.items())
        url_query_string = "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in sorted_query_params_list)
        url = f"{self._BASE_URL}?{url_query_string}"
        try:
            response = requests.request(method.upper(), url, data=body_str.encode('utf-8'), headers=headers)
            response.raise_for_status()
            response_json = response.json()
            metadata = response_json.get('ResponseMetadata', {})
            error = metadata.get('Error')
            if error:
                raise ValueError(f"即梦音乐API错误: Code={error.get('CodeN', error.get('Code',0))}, Message={error.get('Message', 'Unknown error')}")
            return response_json.get('Result', {})
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"即梦音乐 HTTP请求错误: {e}")
        except json.JSONDecodeError:
            raise ValueError(f"无法解析即梦音乐服务器响应: {response.text}")
    def submit_music_generation_task(self, text: str, **kwargs: Any) -> str:
        body = {'Text': text, **kwargs}
        if 'duration' in body and not 1 <= body['duration'] <= 60:
            raise ValueError("音乐时长必须在1到60秒之间。")
        result = self._request(method="POST", action="GenBGMForTime", body=body)
        task_id = result.get('TaskID')
        if not task_id:
            raise ValueError(f"提交即梦音乐任务失败，未能从响应中获取 TaskID。响应: {result}")
        return task_id
    def query_task_status(self, task_id: str) -> Dict[str, Any]:
        return self._request(method="POST", action="QuerySong", body={'TaskID': task_id})
class AIGenerationPipeline:
    def __init__(self):
        self.liblib_client: Optional[LiblibClient] = None
        self.jimeng_i2v_client: Optional[JimengI2VClient] = None
        self.jimeng_music_client: Optional[JimengMusicClient] = None
        self.log_func = print
        self._check_ffmpeg()
        self.temp_dir = os.path.join(os.getcwd(), "temp")
        os.makedirs(self.temp_dir, exist_ok=True)
    def set_clients(self, liblib_client: LiblibClient,
                    jimeng_i2v_client: JimengI2VClient,
                    jimeng_music_client: JimengMusicClient):
        self.liblib_client = liblib_client
        self.jimeng_i2v_client = jimeng_i2v_client
        self.jimeng_music_client = jimeng_music_client
        self.log("所有API客户端已成功设置。")
    def set_logger(self, logger_callable):
        self.log_func = logger_callable
    def log(self, message: str):
        if self.log_func:
            self.log_func(message)
    def _check_ffmpeg(self):
        if not shutil.which("ffmpeg"):
            raise RuntimeError(
                "错误：找不到 FFmpeg。\n"
                "请确保已经安装FFmpeg并将其添加到系统PATH环境变量中。\n"
                "下载地址: https://ffmpeg.org/download.html"
            )
        self.log("FFmpeg 环境检查通过。")
    def _download_file(self, url: str, file_type: str) -> str:
        self.log(f"  [下载] 正在下载{file_type}...")
        ext = ".mp4" if file_type in ["视频", "最终视频"] else ".png" if file_type == "图片" else ".wav"
        unique_filename = f"{str(uuid.uuid4())}_{int(time.time()*1000)}{ext}"
        path = os.path.join(self.temp_dir, unique_filename)
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        self.log(f"  [下载] {file_type}下载完成，保存在: {path}")
        return path
    def generate_image(self, image_params: Dict[str, Any], poll_interval: int = 5, timeout: int = 300) -> Tuple[str, str]:
        if not self.liblib_client: raise RuntimeError("LiblibClient未初始化。")
        self.log("--- [阶段 1/3] 开始执行文生图任务 ---")
        self.log("  [1.1] 提交生图任务至 LibLib...")
        generate_uuid = self.liblib_client.submit_text_to_image_task(image_params)
        self.log(f"  [1.1] 任务提交成功！任务UUID: {generate_uuid}")
        self.log(f"\n  [1.2] 开始轮询任务结果 (每 {poll_interval} 秒一次，预计耗时30秒)...")
        start_time, status_map = time.time(), {1:"等待", 2:"执行中", 3:"已生图", 4:"审核中", 5:"成功", 6:"失败", 7:"超时"}
        while time.time() - start_time < timeout:
            res = self.liblib_client.query_task_status(generate_uuid)
            status = res['data'].get('generateStatus')
            self.log(f"    - LibLib任务状态: {status_map.get(status, f'未知({status})')}...")
            if status == 5:
                self.log("\n  [1.3] 生图任务成功！")
                if not res['data'].get('images') or not isinstance(res['data']['images'], list) or len(res['data']['images']) == 0:
                    raise ValueError(f"LibLib生图任务成功但未返回图片数据。响应: {res}")
                image_url = res['data']['images'][0]['imageUrl']
                self.log(f"      - 图片URL: {image_url}")
                local_path = self._download_file(image_url, "图片")
                return image_url, local_path
            if status in [6, 7]:
                raise RuntimeError(f"LibLib生图任务失败: {res['data'].get('generateMsg', '无详细信息')}")
            time.sleep(poll_interval)
        raise TimeoutError(f"LibLib生图任务在 {timeout} 秒内未能完成。")
    def generate_video(self, image_url: str, video_params: Dict[str, Any], poll_interval: int = 30, timeout: int = 300) -> Tuple[str, str]:
        if not self.jimeng_i2v_client: raise RuntimeError("JimengI2VClient未初始化。")
        self.log("\n--- [阶段 2/3] 开始执行图生视频任务 ---")
        self.log("  [2.1] 提交任务至即梦...")
        task_id = self.jimeng_i2v_client.submit_video_generation_task(image_url, **video_params)
        self.log(f"  [2.1] 任务提交成功！任务ID: {task_id}")
        self.log(f"\n  [2.2] 开始轮询任务结果 (每 {poll_interval} 秒一次，预计耗时5分钟)...")
        start_time = time.time()
        while time.time() - start_time < timeout:
            res = self.jimeng_i2v_client.query_task_status(task_id)
            status = res.get('data', {}).get('status')
            self.log(f"    - 即梦视频任务状态: {status}")
            if status == 'done':
                self.log("\n  [2.3] 视频生成任务成功！")
                video_url = res['data'].get('video_url')
                if not video_url:
                    raise ValueError(f"即梦视频任务成功但未返回视频URL。响应: {res}")
                self.log(f"      - 视频URL: {video_url}")
                local_path = self._download_file(video_url, "视频")
                return video_url, local_path
            if status in ['failed', 'error']:
                raise RuntimeError(f"即梦视频任务失败: {res.get('data')}")
            time.sleep(poll_interval)
        raise TimeoutError(f"即梦视频任务在 {timeout} 秒内未能完成。")
    def generate_music_and_merge(self, video_path: str, music_params: Dict[str, Any], output_path: str, poll_interval: int = 5, timeout: int = 180) -> str:
        if not self.jimeng_music_client: raise RuntimeError("JimengMusicClient未初始化。")
        self.log("\n--- [阶段 3/3] 开始执行文生音乐与合成任务 ---")
        prompt = music_params.get('prompt')
        if not prompt: raise ValueError("音乐生成的提示词不能为空。")
        self.log(f"  [3.1] 提交音乐生成任务，提示词: \"{prompt[:80]}...\"")
        api_specific_kwargs = {k: v for k, v in music_params.items() if k != 'prompt'}
        task_id = self.jimeng_music_client.submit_music_generation_task(prompt, **api_specific_kwargs)
        self.log(f"  [3.1] 任务提交成功！任务ID: {task_id}")
        self.log(f"\n  [3.2] 开始轮询音乐任务结果 (每 {poll_interval} 秒一次)...")
        start_time, status_map = time.time(), {0: "等待", 1: "处理中", 2: "成功", 3: "失败"}
        music_url, music_path = None, None
        while time.time() - start_time < timeout:
            res = self.jimeng_music_client.query_task_status(task_id)
            status = res.get('Status')
            progress = res.get('Progress', 0)
            self.log(f"    - 即梦音乐任务状态: {status_map.get(status, f'未知({status})')}, 进度: {progress}%")
            if status == 2:
                self.log("\n  [3.3] 音乐生成任务成功！")
                music_url = res.get('SongDetail', {}).get('AudioUrl')
                if not music_url:
                     raise ValueError(f"即梦音乐任务成功但未返回音乐URL。响应: {res}")
                self.log(f"      - 音乐URL: {music_url}")
                music_path = self._download_file(music_url, "音乐")
                break
            if status == 3:
                raise RuntimeError(f"即梦音乐任务失败: {res.get('FailureReason')}")
            time.sleep(poll_interval)
        if not music_path:
            raise TimeoutError(f"即梦音乐任务在 {timeout} 秒内未能完成。")
        self.log("\n  [3.4] 开始使用 FFmpeg 合成最终视频...")
        command = ['ffmpeg','-i', video_path,'-i', music_path,'-c:v', 'copy','-c:a', 'aac','-shortest', '-y', output_path]
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8')
            self.log(f"  [3.4] 合成成功！最终文件位于: {output_path}")
            return output_path
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"FFmpeg 合成失败: {e.stderr}")
        finally:
            self.log("  [3.5] 清理临时音乐文件...")
            if music_path and os.path.exists(music_path):
                try:
                    os.remove(music_path)
                    self.log(f"  [3.5] 已删除临时音乐文件: {music_path}")
                except OSError as e:
                    self.log(f"  [3.5] 删除临时音乐文件失败: {e}")
            self.log("  [3.5] 清理完成。")
    def cleanup_temp_files(self):
        self.log("正在清理所有临时文件...")
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                self.log(f"临时文件目录 {self.temp_dir} 清理完毕。")
            except Exception as e:
                self.log(f"清理临时文件时出错: {e}")
        else:
            self.log("临时文件目录不存在，无需清理。")
class VideoThread(QThread):
    change_pixmap_signal = pyqtSignal(np.ndarray)
    finished_signal = pyqtSignal()
    error_signal = pyqtSignal(str)
    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = False
        self._video_path: Optional[str] = None
    def set_video(self, video_path: str):
        self._video_path = video_path
    def run(self):
        if not self._video_path or not os.path.exists(self._video_path):
            self.error_signal.emit(f"视频文件不存在或路径无效: {self._video_path}")
            self.finished_signal.emit()
            return
        self._running = True
        container = None
        try:
            container = av.open(self._video_path)
        except Exception as e:
            self.error_signal.emit(f"无法打开视频文件 '{os.path.basename(self._video_path)}': {e}")
            self.finished_signal.emit()
            return
        try:
            video_stream = next(s for s in container.streams if s.type == 'video')
            fps = float(video_stream.average_rate) if video_stream.average_rate else \
                  (float(video_stream.rate) if video_stream.rate else 30.0)
            if fps <= 0: fps = 30.0
            frame_duration = 1.0 / fps
            start_time = time.time()
            frame_count = 0
            for frame in container.decode(video_stream):
                if not self._running:
                    break
                img = frame.to_rgb().to_ndarray()
                self.change_pixmap_signal.emit(img)
                frame_count += 1
                elapsed_time = time.time() - start_time
                expected_time = frame_count * frame_duration
                sleep_time = expected_time - elapsed_time
                if sleep_time > 0:
                    time.sleep(sleep_time)
                else:
                    QApplication.processEvents()
        except StopIteration:
            self.error_signal.emit(f"视频 '{os.path.basename(self._video_path)}' 中未找到视频流。")
        except Exception as e:
            self.error_signal.emit(f"播放视频 '{os.path.basename(self._video_path)}' 时出错: {e}")
        finally:
            if container:
                container.close()
            self._running = False
            self.finished_signal.emit()
    def stop(self):
        self._running = False
class PromptGenerationStrategy(ABC):
    @abstractmethod
    def get_theme_name(self) -> str:
        pass
    @abstractmethod
    def get_display_options_title(self) -> str:
        pass
    @abstractmethod
    def get_display_options(self) -> List[str]:
        pass
    @abstractmethod
    def get_doubao_system_prompt_template(self) -> str:
        pass
    @abstractmethod
    def get_doubao_user_content_template(self) -> str:
        pass
    def get_default_checkpoint_id(self) -> str:
        return "eb80645cc47a4a65940a105a7daf5632"
    def get_default_loras(self) -> List[Dict[str, Any]]:
        return []
    def get_default_image_prompt(self) -> str:
        return "masterpiece, best quality"
    def get_default_negative_image_prompt(self) -> str:
        return "ng_deepnegative_v1_75t,(badhandv4:1.2),EasyNegative,(worst quality:2),"
    def get_default_image_dimensions(self) -> Tuple[int, int]:
        return (576, 1024)
    def get_default_image_steps(self) -> int:
        return 30
    def get_default_image_cfg_scale(self) -> float:
        return 3.5
    def get_default_image_seed(self) -> int:
        return -1
    def get_default_video_prompt(self) -> str:
        return ""
    def get_default_video_aspect_ratio(self) -> str:
        return "9:16"
    def get_default_video_seed(self) -> int:
        return -1
    def get_default_music_prompt(self) -> str:
        return "Genre: Pop, Mood: Playful, Theme: Fantasy, Instrument: Ukulele, Glockenspiel"
    def get_default_music_duration(self) -> int:
        return 30
class BeautyPromptStrategy(PromptGenerationStrategy):
    def get_theme_name(self) -> str:
        return "美女"
    def get_display_options_title(self) -> str:
        return "选择场景 (选中几项就生成几套):"
    def get_display_options(self) -> List[str]:
        return ["床上", "厨房", "沙滩", "健身房", "卧室", "浴室", "教室", "图书馆", "夜店", "街头", "画室", "咖啡厅", "泳池", "花海", "酒店", "游艇甲板"]
    def get_doubao_system_prompt_template(self) -> str:
        return r"""
            你是一位拥有10年经验的短视频运营专家。你将为用户生成 {count} 套用于打造爆款短视频的材料。
            你需要拆解下列优秀提示词案例，学习这些优秀提示词的设计方法和逻辑，发挥你的创意，设计出不同场景用于LibLib文生图的英文提示词 (对应输出json中的image_prompt)。
            参考的优秀图片提示词案例:
                - A RAW photo,UHD,8k,light particles,advanced filters,texture noise,a high-resolution photo,the photo is a young Asian woman,she has long straight black hair and fair skin,she has a pair of large and expressive brown eyes and a gentle and charming smile,her hair is decorated with black rabbit ears,add a playful and whimsical touch to her appearance. The background shows a modern kitchen with light-colored cabinets and stainless steel countertops. Various kitchen utensils and a bottle of soap dispenser can be seen in the background. The overall aesthetic is simple and playful,focusing on the exquisite features of the subject and the simplicity of the environment. This photo captures A casual moment of daily life emphasizes the youthful innocence and charm of women. The lighting is soft and natural,which enhances the warmth and warmth of the kitchen,the picture exudes a sense of innocence and playfulness,a typical French maid theme,
                - mmgmajiaxian,Xhetong,ar,perfect body,1girl, perfect body, mmgmajiaxian, Xhetong, ar, full-body shot in a portrait style with a solid gray background, complete figure visibility, (holey denim mini skirt: 1.6) (choker microphone + fishnet stockings: 1.5) (wild head toss + saliva splatter: 1.4) (stage lights piercing through the dress: 1.3)
                - 1 gril,Asian portrait,A single portrait of an Asian girl presented in a realistic style. This masterpiece boasts top-notch quality with vibrant and striking colors. She gazes intently at the viewer (to the degree of 1.4),standing sideways with her hands crossed over her chest,wearing a strapless mini skirt,and having ample bust. The photograph captures most of her body contours.,
                - renyu Daily snapshot,The photo shows a beautiful young woman sitting in the office,the environment is both modern and warm. In the background is a light wood-colored partition wall with several art paintings in a minimalist style. She has a healthy,wheat-colored skin,and a long,wavy,light blond hair that spreads casually around her shoulders,exudes a charming luster.,She was dressed in a slim white shirt with a slightly open collar to reveal an elegant neck line,and the sleeves were gently rolled up to reveal her delicate wrists. The lower part of the body was matched with a dark gray hip-wrap skirt,which was just right to show off her slender legs. She sits gracefully,with one hand gently holding her chin and the other hand on her desk,her fingers tapping the table,her eyes focused on the computer screen,as if she were thinking about something important.,Her face is dressed in light makeup,looks fresh and natural,wearing a pair of fashionable round glasses,adding a bit of intellectual charm. A black leather handbag is slung over the shoulder,and the design of the bag is simple and stylish. The light in the office is soft and sufficient,and the sunlight from the window is intertwined with the indoor light,creating a bright and comfortable working atmosphere. The overall scene is full of professional women's capable and soft,people can not help but fall.,
                - 1girl,In the morning, soft light filters through the thin white curtain of the bathroom, creating a hazy and warm atmosphere. A young girl in a simple white halter top and white skirt stands with her back to the camera by the window, her fingers gently touching the curtain.
                - girl,bikini,1girl,have a heavy snow,1girl,bikini,have a heavy snow,bra,Bikini,bra,girl,(masterpiece, gourmet:1.4),fine and meticulous,1 Chinese girl,solo,white skin,perfect figure,standing,(giant breasts:1.2),color printed bikini,(Denim lens:1.2),beach background,
                - FRESHIDEAS Full figured girl,Fresh ideas, a complete character, graceful curves of the waist and hips, naturally large breasts, a young adult female with Chinese nationality, exercising surrounded by various fitness equipment and sports facilities in a gym, wearing a simple black sports bra paired with black tight yoga pants, hair tied into a ponytail, slightly fair skin, a relaxed and confident pose, overall bright, even lighting creating a soft focus, modern, casual, and fashionable style, shot focusing on the components of the subject from feet to full body facing the camera, neutral mood in the image, focused on the subject and her attire, good image quality with clear details, vivid colors, mainly white color palette, smooth and soft texture reflecting the material used in the clothing, neutral and natural body posture, clear and logical finger positioning.
                - lian,large natural breast，,young slim stunning blonde girl, aroused, small perfect tits, tight fit top, tight yoga pants, exposed revealted tits, shirt lift, exposed fit well defined belly, (abs muscles), (lifting her shirt with her hand:1.2), shooting in public street, dim lighting, natural lighting, wear glasses,
                - xianqi,woman,fengyao,fengyao,(((a look of disdain))),(((a disgusted expression))),(pinching with fingers:1.4),solo,1 girl,blush,braided bangs,fashionable hairstyles,sexy pink dress,sexy pink bra,leggings,sexy black stockings (biggest breasts:1.4),extremely big breasts,long legs,curvaceous buttocks,thick thighs,(22yo),soft lighting,romantic atmosphere,dreamy,best quality,masterpiece,close-up,
                - A woman viewed from behind, with medium-sized breasts visible through a loose blouse, wearing a white tank top that accentuates her décolletage, her cheeks blushed. She tilts her head downward, giving a sidelong glance to the viewer, while tying her hair into a ponytail with both hands behind her head, revealing her nape. The shot captures the dynamic and alluring posture from the perspective of her nape extending to her décolletage, with soft lighting enhancing the delicate texture of her skin and clothing. The scene exudes a sensual and intimate atmosphere. High-resolution professional photography, featuring a sophisticated and creative composition.
                - xianqi,fengyao,momo02,fengyao,xianqi,xianqi,woman,fengyao,fengyao,(((a look of disdain))),(((a disgusted expression))),solo,1 girl,blush,braided bangs,fashionable hairstyles,sexy black dress,sexy white bra,leggings,sexy black stockings (biggest breasts:1.4),extremely big breasts,long legs,curvaceous buttocks,thick thighs,(22yo),soft lighting,romantic atmosphere,dreamy,best quality,masterpiece,close-up,indoor,
                - polaroid portrait photography,old polaroid picture,fine detail,neomj,Portrait,Belly Dance,A photograph of a young Asian woman with light skin and long,wavy brown hair. She wears a sparkly,silver bra adorned with colorful gemstones and a matching high-waisted,red skirt with a fringe. Her makeup is glamorous,with red lipstick and dark eyeliner. She stands against a dark,plain background,possibly on a stage,with her arms relaxed by her sides. The image is watermarked with "JAPAN TUSHY" in the bottom right corner.,
                - ( masterpiece ,  lyrics, realistic),  Beautiful woman with long hair wearing a ponytail, purple hair .  big breasts,  beautiful butt ,  nice legs,  slender and voluptuous sexy body , light eyes, a complete beauty .  Wearing gym pants ,  a top fitted to her huge breasts ,  along the coast where in the background you can see the river .
                - xianqi,(((a look of disdain))),(((a disgusted expression))),(pinching with fingers:1.4),solo,1 girl,blush,braided bangs,multicolored hair,sportswear,(biggest breasts:1.4),extremely big breasts,,long legs,curvaceous buttocks,thick thighs,(22yo),soft lighting,romantic atmosphere,dreamy,best quality,masterpiece,close-up,
                - Halooo,wenwen,Giant_breasts,Halooo,A girl with large breasts stands in a room,bathed in soft,warm light filtering through a window behind her. Light penetrates the clothes worn by women,outlining her graceful figure. She is wearing a flowing,sheer white dress that drapes elegantly around her body,creating a gentle cascade of fabric. The dress appears to be made of lightweight material,catching the light and casting subtle shadows.,The woman's hair is styled in an intricate updo,adorned with delicate accessories that add a touch of elegance. Her skin glows softly under the natural light,highlighting her smooth complexion and the delicate features of her face. She holds a single flower in one hand,its petals adding a splash of color to the otherwise monochromatic scene.,Her expression is serene and contemplative,as if lost in thought or admiring the beauty of the flower she holds. The overall atmosphere is calm and peaceful,evoking a sense of tranquility and introspection. The wooden floor and rustic walls add a touch of warmth and simplicity to the setting,enhancing the intimate and timeless feel of the image.,
                - girl,1girl,animal ears,solo,rabbit ears,ring,pink hair,jewelry,blurry background,blurry,fake animal ears,long hair,indoors,dress,pink dress,upper body,bangs,lips,hairband,long sleeves,realistic,frills,depth of field,choker,pink theme,detached sleeves,pink panties,(((from behind))),from_above,(presenting),
                - In Chen Manman's style of photography, a beautiful Chinese high school girl, wearing a white top and plaid skirt, with an old-fashioned canvas bag slung over her shoulder, crouches on the cold grass next to the railway track, the cold grass under the blue sky, a soft light shining on her, a pale face, the background is blurred and hazy, creating an atmosphere of mystery. Looking at the audience. Film lighting, cinematography style, realism, full-body shots, portraits, low Angle angles, this shot captures her entire body from head to toe and presents an ethereal atmosphere. In the infrared photography style, the image has soft light that adds depth and dimension to it.
            你的任务是严格按照下面的JSON格式输出，不要包含任何Markdown标记、代码块标识（如```json）或任何解释性文字。
            直接输出一个包含JSON对象的列表。
            JSON格式要求:
                - 这是一个JSON数组，每个元素是一个对象，代表一套材料。
                - 每个对象包含以下5个键:
                - "scene_description": (string) 用中文简单描述场景。
                - "image_prompt": (string) 用于LibLib图片生成的英文提示词。
                - "music_prompt": (string) 用于即梦AI音乐生成的英文提示词，格式为 "Genre: ..., Mood: ..., Theme: ..., Instrument: ..."。
                - "title": (string) 用于抖音发布的中文爆款标题。
                - "tags": (string) 5个用井号分隔的中文爆款标签。
            注意事项:
                - 由于最终生成的视频时长仅有5秒，所有提示词的长度不易过长，以简短为优。
        """
    def get_doubao_user_content_template(self) -> str:
        return "请为以下几种场景生成材料（美女主题）：{styles}"
    def get_default_checkpoint_id(self) -> str:
        return "eb80645cc47a4a65940a105a7daf5632" # 麦橘超然majicFlus
        # return "412b427ddb674b4dbab9e5abd5ae6057" # F.1基础算法模型-哩布在线可运行
    def get_default_loras(self) -> List[Dict[str, Any]]:
        return [
            {"modelId": "10e5932187ad4b178280a104b3f8c4a6", "weight": 0.8}, # F.1超模好身材美女写真53号_极致逼真人像摄影
            {"modelId": "45df2bd176154f6abb66a63bd609e08a", "weight": 0.6}, # abel 胸（欧派）增大器_不影响其他lora脸型
            {"modelId": "cc8f58889c134e9b84407215793034fd", "weight": 0.3}, # 自然柔软大扔 for Flux_SD1.5时代完美胸型再现
        ]
    def get_default_image_prompt(self) -> str:
        return "RAW photo, masterpiece, best quality, ultrarealistic, photorealistic, 8k, HDR, (photorealistic young Asian woman:1.3), beautiful detailed eyes, beautiful detailed lips, long flowing black hair, wearing a simple elegant white dress, standing in a sun-dappled forest, soft natural lighting, (depth of field:1.2), (bokeh:1.1), serene expression"
    def get_default_negative_image_prompt(self) -> str:
        return "(nsfw), (worst quality:1.4), (low quality:1.4), (normal quality:1.4), blurry, noise, JPEG artifacts, low resolution, low saturation, deformed, ugly, disfigured, poorly drawn face, bad anatomy, mutated, extra limb, missing limb, floating limbs, disconnected limbs, malformed hands, mutated hands and fingers, bad hands, missing fingers, extra fingers, fused fingers, too many fingers, long neck, harsh lighting, cropped, out of frame, duplicate, morbid, mutilated, text, signature, watermark, (unrealistic:1.2), cartoon, anime, 3d render, mutated facial features"
    def get_default_video_prompt(self) -> str:
        return ""
    def get_default_music_prompt(self) -> str:
        return "Genre: Ambient, Mood: Serene, peaceful, Theme: Nature, forest, Instrument: Soft piano, strings, gentle nature sounds"
class LabubuPromptStrategy(PromptGenerationStrategy):
    def get_theme_name(self) -> str:
        return "Labubu"
    def get_display_options_title(self) -> str:
        return "选择风格 (选中几项就生成几套):"
    def get_display_options(self) -> List[str]:
        return ["粉色系", "糖果系", "奶油系", "樱花系", "浪漫系", "童话系", "公主系", "魔法系", "星空系", "森林系", "海洋系", "花漾系", "暖萌系", "治愈系", "软萌系", "复古系"]
    def get_doubao_system_prompt_template(self) -> str:
        return r"""
            你是一位拥有10年经验的短视频运营专家。你将为用户生成 {count} 套用于打造爆款短视频的材料。
            参考的 Lora 模型信息:
                - Prompt words: Labubu, masterpiece, best quality, ultra-detailed, highres, {{prompt}}
                - 核心提示词: Labubu
                - 示例: Labubu in a festive winter wonderland, surrounded by snowflakes and sparkling lights, wearing a warm Santa hat and a bright smile, with a touch of magic in the air.
            你的任务是严格按照下面的JSON格式输出，不要包含任何Markdown标记、代码块标识（如```json）或任何解释性文字。
            直接输出一个包含JSON对象的列表。
            JSON格式要求:
                - 这是一个JSON数组，每个元素是一个对象，代表一套材料。
                - 每个对象包含以下5个键:
                - "scene_description": (string) 用中文简单描述场景。
                - "image_prompt": (string) 用于LibLib图片生成的英文提示词。
                - "music_prompt": (string) 用于即梦AI音乐生成的英文提示词，格式为 "Genre: ..., Mood: ..., Theme: ..., Instrument: ..."。
                - "title": (string) 用于抖音发布的中文爆款标题。
                - "tags": (string) 5个用井号分隔的中文爆款标签。
            注意事项:
                - 由于最终生成的视频时长仅有5秒，所有提示词的长度不易过长，以简短为优。
        """
    def get_doubao_user_content_template(self) -> str:
        return "请为以下几种风格生成材料（Labubu主题）：{styles}"
    def get_default_checkpoint_id(self) -> str:
        return "412b427ddb674b4dbab9e5abd5ae6057"
    def get_default_loras(self) -> List[Dict[str, Any]]:
        return [
            {"modelId": "437e4bcbd77041aba7b4311e292ef853", "weight": 0.8}
        ]
    def get_default_image_prompt(self) -> str:
        return "Labubu, masterpiece, best quality, ultra-detailed, highres, holding a giant sparkling lollipop, floating among colorful clouds, whimsical, magical, bright and cheerful"
    def get_default_negative_image_prompt(self) -> str:
        return "ng_deepnegative_v1_75t,(badhandv4:1.2),EasyNegative,(worst quality:2),"
    def get_default_video_prompt(self) -> str:
        return ""
    def get_default_music_prompt(self) -> str:
        return "Genre: Children's Lullaby, Pop, Mood: Playful, cheerful, Theme: Fantasy, sweets, clouds, Instrument: Ukulele, Glockenspiel, pizzicato strings"
class Worker(QObject):
    log = pyqtSignal(str)
    error = pyqtSignal(str)
    prompts_generated = pyqtSignal(list)
    stream_update = pyqtSignal(str)
    image_generated = pyqtSignal(str, str)
    video_generated = pyqtSignal(str, str)
    final_video_ready = pyqtSignal(str)
    def __init__(self, pipeline: AIGenerationPipeline):
        super().__init__()
        self.pipeline = pipeline
        self.pipeline.set_logger(self.log.emit)
    def run_prompt_generation(self, theme_name: str,
                              system_prompt_template: str,
                              user_content_template: str,
                              selected_options: list,
                              api_key: str):
        try:
            if not selected_options:
                self.error.emit("请至少选择一个提示词风格或场景。")
                return
            if not api_key:
                self.error.emit("请输入豆包 API 密钥。")
                return
            self.log.emit(f"开始为 '{theme_name}' 主题生成 '{'、'.join(selected_options)}' 风格/场景的提示词...")
            key_map = ["scene_description", "image_prompt", "music_prompt", "title", "tags"]
            headers = ["场景描述", "图片提示词", "音乐提示词", "爆款标题", "爆款标签"]
            system_prompt = system_prompt_template.format(count=len(selected_options))
            user_content = user_content_template.format(styles='、'.join(selected_options))
            client = Ark(api_key=api_key)
            stream = client.chat.completions.create(
                model="doubao-seed-1-6-thinking-250615",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content},
                ],
                stream=True
            )
            full_response = ""
            self.log.emit("正在接收豆包API的流式响应...\n\n")
            for chunk in stream:
                if chunk.choices:
                    content = chunk.choices[0].delta.content
                    if content:
                        full_response += content
                        self.stream_update.emit(content)
            self.log.emit("\n响应接收完毕，正在解析JSON...")
            cleaned_response = full_response.strip()
            if cleaned_response.startswith("```json"):
                cleaned_response = cleaned_response[7:]
            if cleaned_response.endswith("```"):
                cleaned_response = cleaned_response[:-3]
            try:
                parsed_json = json.loads(cleaned_response)
                if not isinstance(parsed_json, list) or not all(isinstance(item, dict) for item in parsed_json):
                    raise ValueError("JSON顶层结构不是一个对象列表。")
                rows = []
                for item in parsed_json:
                    row_data = [item.get(key, "") for key in key_map]
                    rows.append(row_data)
                if not rows:
                    self.log.emit("API返回了0套提示词。")
                table_data = [headers] + rows
            except json.JSONDecodeError:
                self.error.emit(f"提示词生成失败: API返回的不是有效的JSON格式。\n原始返回:\n{full_response}")
                return
            except ValueError as e:
                 self.error.emit(f"提示词生成失败: {e}\n原始返回:\n{full_response}")
                 return
            self.log.emit("JSON解析成功，发送结果到主界面。")
            self.prompts_generated.emit(table_data)
        except Exception as e:
            self.error.emit(f"提示词生成过程中发生意外错误: {e}")
            import traceback
            self.log.emit(f"错误追踪: {traceback.format_exc()}")
    def run_image_generation(self, params: Dict[str, Any]):
        try:
            image_url, local_path = self.pipeline.generate_image(params)
            self.image_generated.emit(image_url, local_path)
        except Exception as e:
            self.error.emit(f"图片生成失败: {e}")
    def run_video_generation(self, image_url: str, params: Dict[str, Any]):
        try:
            video_url, local_path = self.pipeline.generate_video(image_url, params)
            self.video_generated.emit(video_url, local_path)
        except Exception as e:
            self.error.emit(f"视频生成失败: {e}")
    def run_music_and_merge(self, video_path: str, music_params: Dict[str, Any], output_path: str):
        try:
            final_path = self.pipeline.generate_music_and_merge(video_path, music_params, output_path)
            self.final_video_ready.emit(final_path)
        except Exception as e:
            self.error.emit(f"音乐生成与合成失败: {e}")
class NoWheelSpinBox(QSpinBox):
    def wheelEvent(self, event):
        event.ignore()
class NoWheelDoubleSpinBox(QDoubleSpinBox):
    def wheelEvent(self, event):
        event.ignore()
class ImageDisplayLabel(QLabel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_pixmap = QPixmap()
        self.setMinimumSize(1, 1)
        self.setAlignment(Qt.AlignCenter)
    def setFullPixmap(self, pixmap: QPixmap):
        self._original_pixmap = pixmap
        self._update_scaled_pixmap()
    def resizeEvent(self, event):
        self._update_scaled_pixmap()
        super().resizeEvent(event)
    def _update_scaled_pixmap(self):
        if not self._original_pixmap.isNull():
            if self.width() > 0 and self.height() > 0:
                scaled_pixmap = self._original_pixmap.scaled(
                    self.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                )
                super().setPixmap(scaled_pixmap)
    def setPixmap(self, pixmap: Optional[QPixmap]):
        if pixmap is None or pixmap.isNull():
            self._original_pixmap = QPixmap()
            super().setPixmap(QPixmap())
        else:
            self._original_pixmap = pixmap
            self._update_scaled_pixmap()
class PlainTextQTextEdit(QTextEdit):
    def insertFromMimeData(self, source):
        if source.hasText():
            self.insertPlainText(source.text())
class CustomTableWidget(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
    def keyPressEvent(self, event):
        if event.key() == Qt.Key_C and (event.modifiers() & Qt.ControlModifier):
            selected_ranges = self.selectedRanges()
            if not selected_ranges:
                super().keyPressEvent(event)
                return
            min_row = min(r.topRow() for r in selected_ranges)
            max_row = max(r.bottomRow() for r in selected_ranges)
            min_col = min(r.leftColumn() for r in selected_ranges)
            max_col = max(r.rightColumn() for r in selected_ranges)
            text_to_copy = ""
            for r_idx in range(min_row, max_row + 1):
                row_texts = []
                for c_idx in range(min_col, max_col + 1):
                    item = self.item(r_idx, c_idx)
                    is_cell_selected = False
                    for s_range in selected_ranges:
                        if (s_range.topRow() <= r_idx <= s_range.bottomRow() and
                            s_range.leftColumn() <= c_idx <= s_range.rightColumn()):
                            is_cell_selected = True
                            break
                    if is_cell_selected:
                        row_texts.append(item.text() if item else "")
                    else:
                        pass
                if row_texts or (c_idx == max_col and r_idx < max_row):
                    text_to_copy += " ".join(row_texts) + "\n"
            QApplication.clipboard().setText(text_to_copy.strip())
            event.accept()
        else:
            super().keyPressEvent(event)
class ReadOnlyDelegateForCopy(QStyledItemDelegate):
    def __init__(self, parent=None):
        super().__init__(parent)
    def createEditor(self, parent_widget: QWidget, option, index) -> QWidget:
        editor = QTextEdit(parent_widget)
        editor.setReadOnly(True)
        editor.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        editor.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        editor.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        editor.setStyleSheet("""
            QTextEdit {
                border: 1px solid #1ABC9C;
                background-color: #4A5160;
                color: #E0E0E0;
                selection-background-color: #1ABC9C;
                selection-color: #FFFFFF;
                padding: 3px;
            }
        """)
        return editor
    def setEditorData(self, editor_widget: QTextEdit, index):
        value = index.model().data(index, Qt.EditRole)
        editor_widget.setPlainText(str(value))
    def setModelData(self, editor_widget: QTextEdit, model, index):
        pass
    def updateEditorGeometry(self, editor_widget: QWidget, option, index):
        editor_widget.setGeometry(option.rect)
class ClickableLabel(QLabel):
    clicked = pyqtSignal(int)
    def __init__(self, text: str, step_id: int, parent=None):
        super().__init__(text, parent)
        self.step_id = step_id
        self.setCursor(Qt.PointingHandCursor)
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.step_id)
        super().mousePressEvent(event)
class MainWindow(QMainWindow):
    start_prompt_generation_task = pyqtSignal(str, str, str, list, str)
    start_image_task = pyqtSignal(dict)
    start_video_task = pyqtSignal(str, dict)
    start_music_task = pyqtSignal(str, dict, str)
    def __init__(self):
        super().__init__()
        self.current_step = 0
        self.is_busy = False
        self.generated_image_url: Optional[str] = None
        self.generated_image_path: Optional[str] = None
        self.generated_video_url: Optional[str] = None
        self.generated_video_path: Optional[str] = None
        self.final_video_path: Optional[str] = None
        self.image_history: List[Tuple[str, str]] = []
        self.current_image_index: int = -1
        self.output_dir = os.path.join(os.getcwd(), "output")
        os.makedirs(self.output_dir, exist_ok=True)
        self.lora_input_widgets: List[Dict[str, QWidget]] = []
        self.MAX_LORAS = 5
        self.prompt_style_checkboxes: List[QCheckBox] = []
        self.prompt_strategies: List[PromptGenerationStrategy] = [
            BeautyPromptStrategy(),
            LabubuPromptStrategy()
        ]
        self.current_prompt_strategy: Optional[PromptGenerationStrategy] = None
        self.pipeline = AIGenerationPipeline()
        self.worker = Worker(self.pipeline)
        self.thread = QThread()
        self.worker.moveToThread(self.thread)
        self.video_thread = VideoThread(self)
        self.init_ui()
        self.load_initial_settings()
        self._connect_signals()
        self.video_thread.change_pixmap_signal.connect(self.update_video_frame)
        self.video_thread.finished_signal.connect(self.on_video_finished_playing)
        self.video_thread.error_signal.connect(self.on_video_playback_error)
        self.thread.start()
        self.center_window()
    def _connect_signals(self):
        self.worker.log.connect(self.log_message)
        self.worker.error.connect(self.on_error)
        self.worker.prompts_generated.connect(self._on_prompts_generated)
        self.worker.stream_update.connect(self.append_log_stream)
        self.worker.image_generated.connect(self.on_image_generated)
        self.worker.video_generated.connect(self.on_video_generated)
        self.worker.final_video_ready.connect(self.on_final_video_ready)
        self.start_prompt_generation_task.connect(self.worker.run_prompt_generation)
        self.start_image_task.connect(self.worker.run_image_generation)
        self.start_video_task.connect(self.worker.run_video_generation)
        self.start_music_task.connect(self.worker.run_music_and_merge)
        self.prompt_theme_combo.currentIndexChanged.connect(self._on_prompt_theme_changed)
    def init_ui(self):
        self.setWindowTitle("颜趣AI视频工作流")
        self.setWindowIcon(QIcon(self.style().standardIcon(QApplication.style().SP_MediaPlay)))
        screen_geometry = QDesktopWidget().availableGeometry()
        width = int(screen_geometry.width() * 0.75)
        height = int(screen_geometry.height() * 0.8)
        self.resize(width, height)
        self.center_window()
        self.setStyleSheet(STYLESHEET)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        settings_panel = self.create_settings_panel()
        main_layout.addWidget(settings_panel, 1)
        workflow_panel = self.create_workflow_panel()
        main_layout.addWidget(workflow_panel, 1)
        menubar = self.menuBar()
        help_menu = menubar.addMenu('帮助')
        tutorial_action = help_menu.addAction('使用教程')
        tutorial_action.triggered.connect(self.open_tutorial_link)
        self.update_workflow_ui_for_step()
    def center_window(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
    def create_settings_panel(self) -> QFrame:
        panel = QFrame()
        panel_layout = QVBoxLayout(panel)
        title = QLabel("参数配置")
        title.setObjectName("TitleLabel")
        panel_layout.addWidget(title)
        self.tabs = QTabWidget()
        keys_widget = QWidget()
        keys_layout = QFormLayout(keys_widget)
        keys_layout.setRowWrapPolicy(QFormLayout.WrapAllRows)
        keys_layout.setVerticalSpacing(15)
        self.doubao_api_key_edit = QLineEdit()
        self.liblib_ak_edit = QLineEdit()
        self.liblib_sk_edit = QLineEdit()
        self.jimeng_ak_edit = QLineEdit()
        self.jimeng_sk_edit = QLineEdit()
        self.doubao_api_key_edit.setEchoMode(QLineEdit.Password)
        self.liblib_sk_edit.setEchoMode(QLineEdit.Password)
        self.jimeng_sk_edit.setEchoMode(QLineEdit.Password)
        keys_layout.addRow("豆包 API Key:", self.doubao_api_key_edit)
        keys_layout.addRow("LibLib Access Key:", self.liblib_ak_edit)
        keys_layout.addRow("LibLib Secret Key:", self.liblib_sk_edit)
        keys_layout.addRow("即梦AI Access Key:", self.jimeng_ak_edit)
        keys_layout.addRow("即梦AI Secret Key:", self.jimeng_sk_edit)
        keys_scroll = QScrollArea()
        keys_scroll.setWidgetResizable(True)
        keys_scroll.setWidget(keys_widget)
        keys_scroll.setStyleSheet("border: none;")
        self.tabs.addTab(keys_scroll, "API 密钥")
        prompt_gen_tab_container = self._create_prompt_gen_tab()
        self.tabs.insertTab(1, prompt_gen_tab_container, "提示词生成")
        img_widget = QWidget()
        img_layout = QFormLayout(img_widget)
        img_layout.setRowWrapPolicy(QFormLayout.WrapAllRows)
        img_layout.setVerticalSpacing(15)
        self.img_prompt_edit = PlainTextQTextEdit()
        self.img_prompt_edit.setFixedHeight(120)
        self.img_neg_prompt_edit = PlainTextQTextEdit()
        self.img_neg_prompt_edit.setFixedHeight(100)
        self.img_model_edit = QLineEdit()
        self.img_width_spin = NoWheelSpinBox()
        self.img_height_spin = NoWheelSpinBox()
        self.img_steps_spin = NoWheelSpinBox()
        self.img_cfg_spin = NoWheelDoubleSpinBox()
        self.img_seed_spin = NoWheelSpinBox()
        self.img_width_spin.setRange(256, 2048); self.img_height_spin.setRange(256, 2048)
        self.img_steps_spin.setRange(1, 150); self.img_cfg_spin.setRange(1.0, 30.0)
        self.img_seed_spin.setRange(-1, 2147483647)
        img_layout.addRow("正向提示词:", self.img_prompt_edit)
        img_layout.addRow("反向提示词:", self.img_neg_prompt_edit)
        img_layout.addRow("Checkpoint UUID:", self.img_model_edit)
        self.lora_section_widget = QWidget()
        self.lora_section_layout = QVBoxLayout(self.lora_section_widget)
        self.lora_section_layout.setContentsMargins(0,0,0,0)
        self.lora_section_layout.setSpacing(5)
        self.lora_inputs_container_layout = QVBoxLayout()
        self.lora_inputs_container_layout.setSpacing(5)
        self.lora_section_layout.addLayout(self.lora_inputs_container_layout)
        img_layout.addRow("LoRA UUID:", self.lora_section_widget)
        img_layout.addRow("宽度:", self.img_width_spin)
        img_layout.addRow("高度:", self.img_height_spin)
        img_layout.addRow("步数:", self.img_steps_spin)
        img_layout.addRow("CFG Scale:", self.img_cfg_spin)
        img_layout.addRow("随机种子:", self.img_seed_spin)
        img_scroll = QScrollArea()
        img_scroll.setWidgetResizable(True)
        img_scroll.setWidget(img_widget)
        img_scroll.setStyleSheet("border: none;")
        self.tabs.addTab(img_scroll, "图像参数")
        av_widget = QWidget()
        av_layout = QFormLayout(av_widget)
        av_layout.setRowWrapPolicy(QFormLayout.WrapAllRows)
        av_layout.setVerticalSpacing(15)
        self.vid_aspect_ratio_combo = QComboBox()
        self.vid_aspect_ratio_combo.addItems(["9:16", "16:9", "4:3", "1:1", "3:4", "21:9", "9:21"])
        self.vid_seed_spin = NoWheelSpinBox()
        self.vid_seed_spin.setRange(-1, 2147483647)
        self.music_prompt_edit = PlainTextQTextEdit()
        self.music_prompt_edit.setFixedHeight(80)
        av_layout.addRow("视频宽高比例:", self.vid_aspect_ratio_combo)
        av_layout.addRow("视频随机种子:", self.vid_seed_spin)
        av_layout.addRow("音乐生成提示词:", self.music_prompt_edit)
        av_scroll = QScrollArea()
        av_scroll.setWidgetResizable(True)
        av_scroll.setWidget(av_widget)
        av_scroll.setStyleSheet("border: none;")
        self.tabs.addTab(av_scroll, "音视频参数")
        panel_layout.addWidget(self.tabs, 1)
        settings_btn_layout = QHBoxLayout()
        self.save_btn = QPushButton("保存当前参数")
        self.reset_btn = QPushButton("恢复主题默认")
        self.save_btn.clicked.connect(self.save_settings_in_session)
        self.reset_btn.clicked.connect(self.load_current_theme_defaults)
        settings_btn_layout.addWidget(self.save_btn)
        settings_btn_layout.addWidget(self.reset_btn)
        panel_layout.addLayout(settings_btn_layout)
        output_layout = QHBoxLayout()
        self.output_path_edit = QLineEdit(self.output_dir)
        self.output_path_edit.setReadOnly(True)
        browse_btn = QPushButton("浏览...")
        browse_btn.clicked.connect(self.select_output_dir)
        output_layout.addWidget(self.output_path_edit)
        output_layout.addWidget(browse_btn)
        form_layout_for_output = QFormLayout()
        form_layout_for_output.addRow("输出目录:", output_layout)
        panel_layout.addLayout(form_layout_for_output)
        return panel
    def _create_prompt_gen_tab(self) -> QScrollArea:
        tab_content_widget = QWidget()
        layout = QVBoxLayout(tab_content_widget)
        layout.setSpacing(15)
        theme_selection_layout = QHBoxLayout()
        theme_label = QLabel("选择生成主题:")
        self.prompt_theme_combo = QComboBox()
        theme_selection_layout.addWidget(theme_label)
        theme_selection_layout.addWidget(self.prompt_theme_combo, 1)
        layout.addLayout(theme_selection_layout)
        self.prompt_styles_group_box = QGroupBox()
        self.prompt_styles_checkbox_layout = QGridLayout(self.prompt_styles_group_box)
        layout.addWidget(self.prompt_styles_group_box)
        self.generate_prompts_btn = QPushButton("生成提示词")
        self.generate_prompts_btn.setObjectName("PrimaryButton")
        self.generate_prompts_btn.clicked.connect(self._start_prompt_generation_process)
        layout.addWidget(self.generate_prompts_btn)
        self.prompt_table = CustomTableWidget()
        self.prompt_table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.prompt_table.verticalHeader().setVisible(True)
        self.prompt_table.verticalHeader().setDefaultAlignment(Qt.AlignCenter)
        self.prompt_table.setAlternatingRowColors(True)
        self.prompt_table.setEditTriggers(QTableWidget.DoubleClicked)
        self.prompt_table.setSelectionBehavior(QTableWidget.SelectItems)
        self.prompt_table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.prompt_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.prompt_table.setWordWrap(True)
        self.read_only_copy_delegate = ReadOnlyDelegateForCopy(self.prompt_table)
        self.prompt_table.setItemDelegate(self.read_only_copy_delegate)
        layout.addWidget(self.prompt_table, 1)
        table_actions_layout = QHBoxLayout()
        self.apply_prompts_btn = QPushButton("应用选中行提示词")
        self.apply_prompts_btn.setObjectName("PrimaryButton")
        self.apply_prompts_btn.clicked.connect(self._apply_generated_prompts_to_params)
        self.prompt_table.itemSelectionChanged.connect(self._update_apply_button_state)
        self.apply_prompts_btn.setEnabled(False)
        table_actions_layout.addStretch()
        table_actions_layout.addWidget(self.apply_prompts_btn)
        table_actions_layout.addStretch()
        layout.addLayout(table_actions_layout)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(tab_content_widget)
        scroll_area.setStyleSheet("border: none;")
        return scroll_area
    def _add_lora_input_row(self, model_id: str = "", weight: float = 0.0, insert_after_row_widget: Optional[QWidget] = None):
        if len(self.lora_input_widgets) >= self.MAX_LORAS:
            if not self.is_busy:
                 QMessageBox.information(self, "提示", f"最多只能添加 {self.MAX_LORAS} 个Lora模型。")
            return
        lora_row_widget = QWidget()
        lora_row_layout = QHBoxLayout(lora_row_widget)
        lora_row_layout.setContentsMargins(0,0,0,0)
        lora_row_layout.setSpacing(5)
        id_label = QLabel("ID:")
        lora_id_edit = QLineEdit(model_id)
        lora_id_edit.setPlaceholderText("Lora模型版本ID")
        weight_label = QLabel("权重:")
        lora_weight_spin = NoWheelDoubleSpinBox()
        lora_weight_spin.setRange(-1.0, 2.0)
        lora_weight_spin.setSingleStep(0.1)
        lora_weight_spin.setValue(weight)
        lora_weight_spin.setDecimals(2)
        remove_button = QPushButton("-")
        remove_button.setObjectName("LoraActionButton")
        remove_button.setFixedWidth(35)
        remove_button.setToolTip("移除此Lora")
        remove_button.clicked.connect(lambda checked, widget_to_remove=lora_row_widget: self._remove_lora_input_row(widget_to_remove))
        add_button_inline = QPushButton("+")
        add_button_inline.setObjectName("LoraActionButton")
        add_button_inline.setFixedWidth(35)
        add_button_inline.setToolTip("在此下方添加新Lora")
        add_button_inline.clicked.connect(lambda checked, current_row_ref=lora_row_widget: self._add_lora_input_row(insert_after_row_widget=current_row_ref))
        lora_row_layout.addWidget(id_label)
        lora_row_layout.addWidget(lora_id_edit, 3)
        lora_row_layout.addWidget(weight_label)
        lora_row_layout.addWidget(lora_weight_spin, 1)
        lora_row_layout.addWidget(remove_button)
        lora_row_layout.addWidget(add_button_inline)
        new_lora_entry = {
            'id_edit': lora_id_edit,
            'weight_spin': lora_weight_spin,
            'row_widget': lora_row_widget,
            'remove_button': remove_button,
            'add_button': add_button_inline
        }
        insert_idx = -1
        if insert_after_row_widget:
            for i, existing_lora_info in enumerate(self.lora_input_widgets):
                if existing_lora_info['row_widget'] == insert_after_row_widget:
                    insert_idx = i + 1
                    break
        if insert_idx != -1:
            self.lora_inputs_container_layout.insertWidget(insert_idx, lora_row_widget)
            self.lora_input_widgets.insert(insert_idx, new_lora_entry)
        else:
            self.lora_inputs_container_layout.addWidget(lora_row_widget)
            self.lora_input_widgets.append(new_lora_entry)
        self._update_lora_buttons_state()
    def _remove_lora_input_row(self, lora_row_widget_to_remove: QWidget):
        if len(self.lora_input_widgets) <= 1:
            return
        widget_info_to_remove = None
        for info in self.lora_input_widgets:
            if info['row_widget'] == lora_row_widget_to_remove:
                widget_info_to_remove = info
                break
        if widget_info_to_remove:
            self.lora_inputs_container_layout.removeWidget(widget_info_to_remove['row_widget'])
            widget_info_to_remove['row_widget'].deleteLater()
            self.lora_input_widgets.remove(widget_info_to_remove)
            self._update_lora_buttons_state()
    def _update_lora_buttons_state(self):
        num_loras = len(self.lora_input_widgets)
        can_add_more = num_loras < self.MAX_LORAS
        can_remove_any = num_loras > 1
        for info in self.lora_input_widgets:
            info['add_button'].setEnabled(can_add_more)
            info['remove_button'].setEnabled(can_remove_any)
    def _clear_all_lora_inputs(self):
        for i in reversed(range(len(self.lora_input_widgets))):
            info = self.lora_input_widgets.pop(i)
            self.lora_inputs_container_layout.removeWidget(info['row_widget'])
            info['row_widget'].deleteLater()
        self.lora_input_widgets.clear()
    def create_workflow_panel(self) -> QFrame:
        panel = QFrame()
        panel_layout = QVBoxLayout(panel)
        step_layout = QHBoxLayout()
        step_layout.setSpacing(15)
        self.step1_label = ClickableLabel("① 文生图", 1)
        self.step2_label = ClickableLabel("② 图生视频", 2)
        self.step3_label = ClickableLabel("③ 文生音乐 & 合成", 3)
        for label in [self.step1_label, self.step2_label, self.step3_label]:
            label.setObjectName("StepLabel")
            label.clicked.connect(self.handle_step_selection)
            step_layout.addWidget(label)
        step_layout.addStretch()
        panel_layout.addLayout(step_layout)
        self.media_display_widget = QWidget()
        media_layout = QVBoxLayout(self.media_display_widget)
        media_layout.setContentsMargins(0, 0, 0, 0)
        self.image_label = ImageDisplayLabel("点击“开始生成”启动流程")
        self.image_label.setObjectName("MediaPlaceholder")
        self.image_label.setAlignment(Qt.AlignCenter)
        media_layout.addWidget(self.image_label)
        self.image_nav_widget = QWidget()
        image_nav_layout = QHBoxLayout(self.image_nav_widget)
        image_nav_layout.setContentsMargins(0, 5, 0, 5)
        self.prev_image_btn = QPushButton("上一张")
        self.next_image_btn = QPushButton("下一张")
        self.image_history_label = QLabel("")
        self.image_history_label.setAlignment(Qt.AlignCenter)
        self.prev_image_btn.clicked.connect(self.show_previous_image)
        self.next_image_btn.clicked.connect(self.show_next_image)
        image_nav_layout.addStretch()
        image_nav_layout.addWidget(self.prev_image_btn)
        image_nav_layout.addWidget(self.image_history_label)
        image_nav_layout.addWidget(self.next_image_btn)
        image_nav_layout.addStretch()
        media_layout.addWidget(self.image_nav_widget)
        self.image_nav_widget.hide()
        self.video_control_widget = QWidget()
        video_control_layout = QHBoxLayout(self.video_control_widget)
        video_control_layout.setContentsMargins(0, 5, 0, 5)
        self.replay_btn = QPushButton("🔄 重播")
        self.replay_btn.clicked.connect(self.handle_replay_click)
        video_control_layout.addStretch()
        video_control_layout.addWidget(self.replay_btn)
        video_control_layout.addStretch()
        media_layout.addWidget(self.video_control_widget)
        self.video_control_widget.hide()
        panel_layout.addWidget(self.media_display_widget, 1)
        self.loading_label = QLabel()
        loading_gif_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "loading.gif")
        if os.path.exists(loading_gif_path):
             self.movie = QMovie(loading_gif_path)
        else:
             self.movie = QMovie()
             print(f"警告: loading.gif 未在路径 {loading_gif_path} 找到。")
        if not self.movie.isValid():
            self.loading_label.setText("处理中，请稍候...")
            self.loading_label.setAlignment(Qt.AlignCenter)
            self.loading_label.setStyleSheet("font-size: 18px; color: #1ABC9C;")
        else:
             self.loading_label.setMovie(self.movie)
        self.loading_label.hide()
        media_layout.addWidget(self.loading_label, 0, Qt.AlignCenter)
        control_layout = QHBoxLayout()
        self.start_btn = QPushButton("开始生成")
        self.retry_btn = QPushButton("重新生成当前步骤")
        self.next_btn = QPushButton("下一步")
        self.start_btn.setObjectName("PrimaryButton")
        self.retry_btn.setObjectName("RestartButton")
        self.next_btn.setObjectName("PrimaryButton")
        self.start_btn.setFixedHeight(40)
        self.retry_btn.setFixedHeight(40)
        self.next_btn.setFixedHeight(40)
        control_layout.addStretch()
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.retry_btn)
        control_layout.addWidget(self.next_btn)
        control_layout.addStretch()
        self.start_btn.clicked.connect(self.start_main_generation_flow)
        self.retry_btn.clicked.connect(self.retry_current_step_generation)
        self.next_btn.clicked.connect(self.proceed_to_next_step)
        panel_layout.addLayout(control_layout)
        log_label = QLabel("运行日志")
        log_label.setStyleSheet("font-size: 16px; font-weight: bold; margin-top: 15px;")
        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setFixedHeight(180)
        panel_layout.addWidget(log_label)
        panel_layout.addWidget(self.log_widget)
        self.update_workflow_ui_for_step()
        return panel
    def load_initial_settings(self):
        self.doubao_api_key_edit.setText(os.getenv("DOUBAO_API_KEY", ""))
        self.liblib_ak_edit.setText(os.getenv("LIBLIB_AK", ""))
        self.liblib_sk_edit.setText(os.getenv("LIBLIB_SK", ""))
        self.jimeng_ak_edit.setText(os.getenv("JIMENG_AK", ""))
        self.jimeng_sk_edit.setText(os.getenv("JIMENG_SK", ""))
        self._populate_prompt_theme_combo()
        self.log_message("请输入您的API密钥并开始创作。")
    def open_tutorial_link(self):
        tutorial_url = "https://www.yuque.com/"
        QDesktopServices.openUrl(QUrl(tutorial_url))
        self.log_message(f"正在打开使用教程: {tutorial_url}")
    def start_main_generation_flow(self):
        if self.start_btn.text() == "全部重来":
            self.reset_entire_workflow()
            return
        if self.is_busy: return
        if not self._initialize_api_clients(): return
        self.set_busy_state(True)
        try:
            self.log_widget.clear()
            self.log_message("开始图片生成流程...")
            image_params = self.get_image_generation_params()
            self.start_image_task.emit(image_params)
        except Exception as e:
            self.on_error(f"准备图片生成时出错: {e}")
    def proceed_to_next_step(self):
        if self.is_busy: return
        if not self._initialize_api_clients(): return
        self.set_busy_state(True)
        next_task_name = ""
        try:
            if self.current_step == 1:
                next_task_name = "视频"
                if not self.generated_image_url:
                    self.on_error("无法进行视频生成：缺少源图片URL。请先生成图片。")
                    return
                video_params = self.get_video_generation_params()
                self.start_video_task.emit(self.generated_image_url, video_params)
            elif self.current_step == 2:
                next_task_name = "音乐与合成"
                if not self.generated_video_path:
                    self.on_error("无法进行音乐合成：缺少源视频路径。请先生成视频。")
                    return
                music_params = self.get_music_generation_params()
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                theme_name_safe = "video"
                if self.current_prompt_strategy:
                    theme_name_safe = "".join(c if c.isalnum() else "_" for c in self.current_prompt_strategy.get_theme_name())
                final_filename = f"final_video_{theme_name_safe}_{timestamp}.mp4"
                os.makedirs(self.output_dir, exist_ok=True)
                self.final_video_path = os.path.join(self.output_dir, final_filename)
                self.start_music_task.emit(
                    self.generated_video_path,
                    music_params,
                    self.final_video_path
                )
        except Exception as e:
            self.on_error(f"准备进行下一步 ({next_task_name}) 时出错: {e}")
    def retry_current_step_generation(self):
        if self.is_busy: return
        if not self._initialize_api_clients(): return
        self.set_busy_state(True)
        current_task_name = ""
        try:
            if self.current_step == 1:
                current_task_name = "图片"
                image_params = self.get_image_generation_params()
                self.start_image_task.emit(image_params)
            elif self.current_step == 2:
                current_task_name = "视频"
                if not self.generated_image_url:
                    self.on_error("无法重试视频生成：缺少源图片URL。请先生成图片。")
                    return
                video_params = self.get_video_generation_params()
                self.start_video_task.emit(self.generated_image_url, video_params)
        except Exception as e:
            self.on_error(f"准备重试{current_task_name}生成时出错: {e}")
    def reset_entire_workflow(self):
        self.current_step = 0
        self.is_busy = False
        self.generated_image_url = None
        self.generated_image_path = None
        self.generated_video_url = None
        self.generated_video_path = None
        self.final_video_path = None
        self.image_history.clear()
        self.current_image_index = -1
        self.image_nav_widget.hide()
        self.video_control_widget.hide()
        self.replay_btn.setEnabled(False)
        self.stop_current_video_playback()
        self.image_label.setPixmap(None)
        self.image_label.setText("点击“开始生成”启动流程")
        self.image_label.setObjectName("MediaPlaceholder")
        self.image_label.style().unpolish(self.image_label)
        self.image_label.style().polish(self.image_label)
        self.log_widget.clear()
        self.log_message("工作流已重置。您可以选择新主题、生成提示词，或直接使用当前参数开始生成。")
        self.update_workflow_ui_for_step()
    def on_error(self, error_msg: str):
        if hasattr(self, 'generate_prompts_btn') and self.generate_prompts_btn:
            self.generate_prompts_btn.setEnabled(True)
            self.generate_prompts_btn.setText("生成提示词")
            self.set_busy_state(False)
            self.log_message(f"[错误] {error_msg}")
            QMessageBox.critical(self, "发生错误", str(error_msg))
    def on_image_generated(self, image_url: str, local_path: str):
        self.current_step = 1
        if self.current_image_index < len(self.image_history) - 1:
            self.image_history = self.image_history[:self.current_image_index + 1]
        self.image_history.append((image_url, local_path))
        self.current_image_index = len(self.image_history) - 1
        self.stop_current_video_playback()
        self._display_current_image()
        self.set_busy_state(False)
        self.log_message(f"✅ 图片生成成功！(当前共 {len(self.image_history)} 张历史图片)")
    def on_video_generated(self, video_url: str, local_path: str):
        self.current_step = 2
        self.generated_video_url = video_url
        self.generated_video_path = local_path
        if not os.path.exists(local_path) or os.path.getsize(local_path) == 0:
            self.on_error(f"视频文件下载失败或为空: {local_path}")
            return
        self.stop_current_video_playback()
        self.image_label.setPixmap(None)
        self.image_label.setText("")
        self.image_label.setObjectName("")
        self.image_label.style().unpolish(self.image_label); self.image_label.style().polish(self.image_label)
        self.video_thread.set_video(local_path)
        self.video_thread.start()
        self.update_replay_button_state()
        self.set_busy_state(False)
        self.log_message(f"✅ 无声视频生成成功！")
    def on_final_video_ready(self, final_video_path: str):
        self.current_step = 3
        self.final_video_path = final_video_path
        if not os.path.exists(final_video_path) or os.path.getsize(final_video_path) == 0:
            self.on_error(f"最终视频文件生成失败或为空: {final_video_path}")
            return
        self.stop_current_video_playback()
        self.image_label.setPixmap(None)
        self.image_label.setText("")
        self.image_label.setObjectName("")
        self.image_label.style().unpolish(self.image_label); self.image_label.style().polish(self.image_label)
        self.video_thread.set_video(final_video_path)
        self.video_thread.start()
        self.update_replay_button_state()
        self.set_busy_state(False)
        self.log_message(f"🎉🎉🎉 全部任务完成！最终视频已生成。")
        QMessageBox.information(self, "任务完成", f"视频已成功生成并保存到：\n{final_video_path}")
        self.update_workflow_ui_for_step()
    def _on_prompts_generated(self, data: list):
        self.generate_prompts_btn.setEnabled(True)
        self.generate_prompts_btn.setText("生成提示词")
        if not data or len(data) < 1:
            self.log_message("[错误] 未能从API获取有效表格数据结构。")
            self.prompt_table.clearContents()
            self.prompt_table.setRowCount(0)
            self.prompt_table.setColumnCount(0)
            return
        try:
            headers = data[0]
            rows_data = data[1:]
            self.prompt_table.clearContents()
            self.prompt_table.setRowCount(0)
            self.prompt_table.setColumnCount(len(headers))
            self.prompt_table.setHorizontalHeaderLabels(headers)
            if not rows_data:
                self.log_message("API返回了0套提示词。")
                return
            self.prompt_table.setRowCount(len(rows_data))
            for row_idx, row_content_list in enumerate(rows_data):
                for col_idx, cell_content in enumerate(row_content_list):
                    item = QTableWidgetItem(str(cell_content))
                    self.prompt_table.setItem(row_idx, col_idx, item)
                self.prompt_table.setVerticalHeaderItem(row_idx, QTableWidgetItem(str(row_idx + 1)))
            self.prompt_table.resizeRowsToContents()
            self.log_message(f"成功生成并展示了 {len(rows_data)} 套提示词。")
        except Exception as e:
            self.on_error(f"填充提示词表格时出错: {e}")
    def handle_step_selection(self, step_id_clicked: int):
        if self.is_busy:
            self.log_message("任务正在进行中，请勿切换步骤。")
            return
        target_tab_name = None
        can_jump = False
        if step_id_clicked == 1:
            can_jump = True
            target_tab_name = "图像参数"
            if self.image_history:
                self._display_current_image()
                self.video_control_widget.hide()
                self.image_nav_widget.show()
            else:
                self.image_label.setPixmap(None)
                self.image_label.setText("点击“开始生成”启动流程")
                self.image_label.setObjectName("MediaPlaceholder")
                self.image_label.style().unpolish(self.image_label); self.image_label.style().polish(self.image_label)
                self.video_control_widget.hide()
                self.image_nav_widget.hide()
        elif step_id_clicked == 2:
            if self.current_step >= 1 or self.image_history:
                can_jump = True
                target_tab_name = "视频参数"
                if self.generated_video_path:
                    self.stop_current_video_playback()
                    self.video_thread.set_video(self.generated_video_path)
                    self.video_thread.start()
                    self.update_replay_button_state()
                    self.image_nav_widget.hide()
                elif self.image_history:
                    self._display_current_image()
                    self.video_control_widget.hide()
                    self.image_nav_widget.show()
            else:
                self.log_message("无法跳转：请先生成至少一张图片。")
        elif step_id_clicked == 3:
            if self.current_step < 2:
                self.log_message("无法跳转：请先完成图生视频步骤。")
            elif self.current_step == 2:
                self.log_message("请点击工作流下方的“合成最终视频”按钮以进入音乐与合成步骤的参数配置与执行。")
            elif self.current_step >= 3:
                can_jump = True
                target_tab_name = "音乐参数"
                if self.final_video_path:
                    self.stop_current_video_playback()
                    self.video_thread.set_video(self.final_video_path)
                    self.video_thread.start()
                    self.update_replay_button_state()
                    self.image_nav_widget.hide()
                elif self.generated_video_path:
                    self.stop_current_video_playback()
                    self.video_thread.set_video(self.generated_video_path)
                    self.video_thread.start()
                    self.update_replay_button_state()
                    self.image_nav_widget.hide()
        if can_jump and target_tab_name:
            for i in range(self.tabs.count()):
                if self.tabs.tabText(i) == target_tab_name:
                    self.tabs.setCurrentIndex(i)
                    break
            self.log_message(f"已手动切换到查看 '{target_tab_name}' 参数。主流程状态为步骤 {self.current_step+1 if self.current_step <3 else '完成'}")
            self.update_step_indicator()
            self.update_workflow_ui_for_step()
    def handle_replay_click(self):
        if not self.video_thread:
            return
        if not self.video_thread.isRunning():
            current_video_to_play = None
            if self.current_step == 3 and self.final_video_path and os.path.exists(self.final_video_path):
                current_video_to_play = self.final_video_path
                self.log_message("重播最终合成视频...")
            elif self.current_step == 2 and self.generated_video_path and os.path.exists(self.generated_video_path):
                current_video_to_play = self.generated_video_path
                self.log_message("重播图生视频...")
            if current_video_to_play:
                self.video_thread.set_video(current_video_to_play)
                self.video_thread.start()
                self.update_replay_button_state()
            else:
                self.log_message("没有可重播的视频。")
        else:
            self.log_message("视频正在播放中，请等待播放结束后重播。")
    def show_previous_image(self):
        if self.current_image_index > 0:
            self.current_image_index -= 1
            self._display_current_image()
    def show_next_image(self):
        if self.current_image_index < len(self.image_history) - 1:
            self.current_image_index += 1
            self._display_current_image()
    def _on_prompt_theme_changed(self, index: int):
        selected_strategy = self.prompt_theme_combo.itemData(index)
        if not isinstance(selected_strategy, PromptGenerationStrategy):
            self.log_message(f"警告：未能从下拉框获取有效的策略对象 (索引: {index})。")
            if not self.prompt_strategies: return
            selected_strategy = self.prompt_strategies[0]
        self.current_prompt_strategy = selected_strategy
        for cb in self.prompt_style_checkboxes:
            self.prompt_styles_checkbox_layout.removeWidget(cb)
            cb.deleteLater()
        self.prompt_style_checkboxes.clear()
        self.prompt_styles_group_box.setTitle(self.current_prompt_strategy.get_display_options_title())
        options = self.current_prompt_strategy.get_display_options()
        cols_per_row = 4 if self.current_prompt_strategy.get_theme_name() == "美女" else 4
        row, col = 0, 0
        for option_name in options:
            checkbox = QCheckBox(option_name)
            self.prompt_style_checkboxes.append(checkbox)
            self.prompt_styles_checkbox_layout.addWidget(checkbox, row, col)
            col += 1
            if col >= cols_per_row:
                col = 0
                row += 1
        self._load_defaults_from_strategy(self.current_prompt_strategy)
    def _start_prompt_generation_process(self):
        if not self.current_prompt_strategy:
            QMessageBox.warning(self, "错误", "未选择任何提示词生成主题。")
            return
        selected_options = [cb.text() for cb in self.prompt_style_checkboxes if cb.isChecked()]
        if not selected_options:
            QMessageBox.warning(self, "提示", f"请至少选择一个{self.current_prompt_strategy.get_display_options_title().split('(')[0].replace('选择', '')}。")
            return
        api_key = self.doubao_api_key_edit.text().strip()
        if not api_key:
            QMessageBox.warning(self, "提示", "请在“API密钥”标签页中输入豆包API Key。")
            self.tabs.setCurrentIndex(0)
            return
        self.generate_prompts_btn.setEnabled(False)
        self.generate_prompts_btn.setText("生成中...")
        self.log_message(f"正在为主题 '{self.current_prompt_strategy.get_theme_name()}' 请求生成提示词...")
        system_template = self.current_prompt_strategy.get_doubao_system_prompt_template()
        user_template = self.current_prompt_strategy.get_doubao_user_content_template()
        self.start_prompt_generation_task.emit(
            self.current_prompt_strategy.get_theme_name(),
            system_template,
            user_template,
            selected_options,
            api_key
        )
    def _update_apply_button_state(self):
        self.apply_prompts_btn.setEnabled(len(self.prompt_table.selectedItems()) > 0)
    def _apply_generated_prompts_to_params(self):
        selected_items = self.prompt_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "提示", "请先在表格中选择一行提示词。")
            return
        current_row = selected_items[0].row()
        try:
            headers_from_table = [self.prompt_table.horizontalHeaderItem(i).text() for i in range(self.prompt_table.columnCount())]
            field_to_header_map = {
                'img_prompt': "图片提示词",
                'music_prompt': "音乐提示词"
            }
            applied_log_parts = []
            def get_cell_text_by_header(row_idx, header_name):
                if header_name in headers_from_table:
                    col_idx = headers_from_table.index(header_name)
                    item = self.prompt_table.item(row_idx, col_idx)
                    return item.text() if item else ""
                return None
            img_p = get_cell_text_by_header(current_row, field_to_header_map['img_prompt'])
            mus_p = get_cell_text_by_header(current_row, field_to_header_map['music_prompt'])
            if img_p is not None:
                self.img_prompt_edit.setText(img_p)
                applied_log_parts.append("图像")
            if mus_p is not None:
                self.music_prompt_edit.setText(mus_p)
                applied_log_parts.append("音乐")
            if applied_log_parts:
                log_msg = f"已将第 {current_row + 1} 行的提示词应用到: {', '.join(applied_log_parts)} 参数。"
                self.log_message(log_msg)
                QMessageBox.information(self, "成功", "提示词已成功应用！")
                for i in range(self.tabs.count()):
                    if self.tabs.tabText(i) == "图像参数":
                        self.tabs.setCurrentIndex(i)
                        break
            else:
                QMessageBox.warning(self, "提示", "未能从选中行应用任何提示词。请检查表格列名是否正确。")
        except Exception as e:
            self.on_error(f"应用提示词时出错: {e}")
    def save_settings_in_session(self):
        if self._initialize_api_clients():
            self.log_message("参数已在当前会话中应用 (API客户端已使用当前密钥更新)。")
            QMessageBox.information(self, "应用成功", "当前填写的参数(特别是API密钥)已应用！")
    def load_current_theme_defaults(self):
        if self.current_prompt_strategy:
            self._load_defaults_from_strategy(self.current_prompt_strategy)
            self.log_message(f"已为主题 '{self.current_prompt_strategy.get_theme_name()}' 恢复默认参数。")
        else:
            self.log_message("错误：未选择任何主题，无法恢复默认参数。")
    def select_output_dir(self):
        directory = QFileDialog.getExistingDirectory(self, "选择输出目录", self.output_dir)
        if directory:
            self.output_dir = directory
            self.output_path_edit.setText(self.output_dir)
            os.makedirs(self.output_dir, exist_ok=True)
            self.log_message(f"输出目录已更新为: {self.output_dir}")
    def set_busy_state(self, busy: bool):
        self.is_busy = busy
        self.update_workflow_ui_for_step()
        QApplication.processEvents()
    def update_workflow_ui_for_step(self):
        self.update_step_indicator()
        if self.is_busy:
            self.start_btn.hide()
            self.retry_btn.hide()
            self.next_btn.hide()
            self.loading_label.show()
            if self.movie and self.movie.isValid(): self.movie.start()
            if hasattr(self, 'generate_prompts_btn'): self.generate_prompts_btn.setEnabled(False)
        else:
            self.loading_label.hide()
            if self.movie and self.movie.isValid(): self.movie.stop()
            if hasattr(self, 'generate_prompts_btn'): self.generate_prompts_btn.setEnabled(True)
            if self.current_step == 0:
                self.start_btn.show()
                self.retry_btn.hide()
                self.next_btn.hide()
                self.start_btn.setText("开始生成图片")
            elif self.current_step == 1:
                self.start_btn.hide()
                self.retry_btn.show()
                self.next_btn.show()
                self.retry_btn.setText("重试生图")
                self.next_btn.setText("生成视频")
            elif self.current_step == 2:
                self.start_btn.hide()
                self.retry_btn.show()
                self.next_btn.show()
                self.retry_btn.setText("重试生视频")
                self.next_btn.setText("合成最终视频")
            elif self.current_step == 3:
                self.start_btn.show()
                self.retry_btn.hide()
                self.next_btn.hide()
                self.start_btn.setText("全部重来")
    def update_step_indicator(self):
        self.step1_label.setProperty("active", self.current_step >= 1 and not self.is_busy)
        self.step2_label.setProperty("active", self.current_step >= 2 and not self.is_busy)
        self.step3_label.setProperty("active", self.current_step >= 3 and not self.is_busy)
        if self.is_busy:
            if self.current_step == 0: self.step1_label.setProperty("active", True)
            elif self.current_step == 1: self.step2_label.setProperty("active", True)
            elif self.current_step == 2: self.step3_label.setProperty("active", True)
        for label in [self.step1_label, self.step2_label, self.step3_label]:
            label.style().unpolish(label)
            label.style().polish(label)
    def update_replay_button_state(self):
        if not self.video_thread:
            if hasattr(self, 'replay_btn'): self.replay_btn.setEnabled(False)
            self.video_control_widget.hide()
            return
        self.video_control_widget.show()
        if self.video_thread.isRunning():
            self.replay_btn.setEnabled(False)
            self.replay_btn.setText("播放中...")
        else:
            self.replay_btn.setEnabled(True)
            self.replay_btn.setText("🔄 重播")
    def log_message(self, msg: str):
        self.log_widget.append(msg)
        self.log_widget.verticalScrollBar().setValue(self.log_widget.verticalScrollBar().maximum())
    def append_log_stream(self, text: str):
        cursor = self.log_widget.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        self.log_widget.ensureCursorVisible()
    def _display_current_image(self):
        if not (0 <= self.current_image_index < len(self.image_history)):
            self.image_nav_widget.hide()
            return
        self.generated_image_url, self.generated_image_path = self.image_history[self.current_image_index]
        pixmap = QPixmap(self.generated_image_path)
        if pixmap.isNull():
            self.on_error(f"历史图片加载失败: {self.generated_image_path}")
            self.image_label.setText("历史图片加载失败")
        else:
            self.image_label.setFullPixmap(pixmap)
            self.image_label.setObjectName("")
        self.image_label.style().unpolish(self.image_label)
        self.image_label.style().polish(self.image_label)
        self.image_history_label.setText(f"图 {self.current_image_index + 1} / {len(self.image_history)}")
        self.prev_image_btn.setEnabled(self.current_image_index > 0)
        self.next_image_btn.setEnabled(self.current_image_index < len(self.image_history) - 1)
        self.image_nav_widget.show()
    def stop_current_video_playback(self):
        if self.video_thread and self.video_thread.isRunning():
            self.video_thread.stop()
            self.video_thread.wait(1500)
    def update_video_frame(self, frame_array: np.ndarray):
        h, w, ch = frame_array.shape
        bytes_per_line = ch * w
        qt_image = QImage(frame_array.data, w, h, bytes_per_line, QImage.Format_RGB888)
        pixmap_to_show = QPixmap.fromImage(qt_image)
        self.image_label.setPixmap(pixmap_to_show)
    def on_video_finished_playing(self):
        video_name = ""
        if self.video_thread and self.video_thread._video_path:
            video_name = os.path.basename(self.video_thread._video_path)
        self.log_message(f"视频 '{video_name}' 播放完毕。")
        if hasattr(self, 'replay_btn'):
            self.replay_btn.setEnabled(True)
            self.replay_btn.setText("🔄 重播")
        if hasattr(self, 'video_control_widget') and not self.video_control_widget.isVisible():
            self.video_control_widget.show()
    def on_video_playback_error(self, error_msg: str):
        self.log_message(f"[视频播放错误] {error_msg}")
        self.image_label.setText("视频播放错误")
        self.image_label.setObjectName("MediaPlaceholder")
        self.image_label.style().unpolish(self.image_label); self.image_label.style().polish(self.image_label)
    def _initialize_api_clients(self) -> bool:
        try:
            if not all([self.liblib_ak_edit.text().strip(), self.liblib_sk_edit.text().strip(),
                        self.jimeng_ak_edit.text().strip(), self.jimeng_sk_edit.text().strip()]):
                api_tab_index = 0
                for i in range(self.tabs.count()):
                    if self.tabs.tabText(i) == "API 密钥":
                        api_tab_index = i
                        break
                self.tabs.setCurrentIndex(api_tab_index)
                QMessageBox.warning(self, "API密钥缺失", "部分或全部API密钥未填写。请检查“API 密钥”标签页。")
                return False
            liblib_client = LiblibClient(self.liblib_ak_edit.text().strip(), self.liblib_sk_edit.text().strip())
            jimeng_i2v_client = JimengI2VClient(self.jimeng_ak_edit.text().strip(), self.jimeng_sk_edit.text().strip())
            jimeng_music_client = JimengMusicClient(self.jimeng_ak_edit.text().strip(), self.jimeng_sk_edit.text().strip())
            self.pipeline.set_clients(liblib_client, jimeng_i2v_client, jimeng_music_client)
            return True
        except ValueError as e:
            self.on_error(f"API客户端初始化失败: {e}")
            return False
        except Exception as e:
            self.on_error(f"设置API客户端时发生未知错误: {e}")
            return False
    def get_image_generation_params(self) -> Dict[str, Any]:
        additional_network = []
        for lora_widget_group in self.lora_input_widgets:
            model_id = lora_widget_group['id_edit'].text().strip()
            weight = lora_widget_group['weight_spin'].value()
            if model_id:
                additional_network.append({"modelId": model_id, "weight": weight})
            elif weight != 0.0:
                 self.log_message(f"[警告] Lora权重 {weight} 已设置但ID为空，此条目将被忽略。")
        return {
            "checkPointId": self.img_model_edit.text().strip(),
            "prompt": self.img_prompt_edit.toPlainText().strip(),
            "negativePrompt": self.img_neg_prompt_edit.toPlainText().strip(),
            "width": self.img_width_spin.value(),
            "height": self.img_height_spin.value(),
            "steps": self.img_steps_spin.value(),
            "cfgScale": self.img_cfg_spin.value(),
            "seed": self.img_seed_spin.value(),
            "imgCount": 1,
            "additionalNetwork": additional_network if additional_network else None,
        }
    def get_video_generation_params(self) -> Dict[str, Any]:
        return {
            "prompt": "",
            "seed": self.vid_seed_spin.value(),
            "aspect_ratio": self.vid_aspect_ratio_combo.currentText(),
        }
    def get_music_generation_params(self) -> Dict[str, Any]:
        return {
            "prompt": self.music_prompt_edit.toPlainText().strip(),
            "duration": 30,
        }
    def _populate_prompt_theme_combo(self):
        self.prompt_theme_combo.clear()
        for strategy in self.prompt_strategies:
            self.prompt_theme_combo.addItem(strategy.get_theme_name(), userData=strategy)
        if self.prompt_strategies:
            self.current_prompt_strategy = self.prompt_strategies[0]
            self._on_prompt_theme_changed(0)
    def _load_defaults_from_strategy(self, strategy: PromptGenerationStrategy):
        self.img_model_edit.setText(strategy.get_default_checkpoint_id())
        self._clear_all_lora_inputs()
        default_loras = strategy.get_default_loras()
        if default_loras:
            for lora in default_loras:
                self._add_lora_input_row(lora.get("modelId", ""), lora.get("weight", 0.0))
        else:
            self._add_lora_input_row()
        self._update_lora_buttons_state()
        self.img_prompt_edit.setText(strategy.get_default_image_prompt())
        self.img_neg_prompt_edit.setText(strategy.get_default_negative_image_prompt())
        img_w, img_h = strategy.get_default_image_dimensions()
        self.img_width_spin.setValue(img_w)
        self.img_height_spin.setValue(img_h)
        self.img_steps_spin.setValue(strategy.get_default_image_steps())
        self.img_cfg_spin.setValue(strategy.get_default_image_cfg_scale())
        self.img_seed_spin.setValue(strategy.get_default_image_seed())
        self.vid_aspect_ratio_combo.setCurrentText(strategy.get_default_video_aspect_ratio())
        self.vid_seed_spin.setValue(strategy.get_default_video_seed())
        self.music_prompt_edit.setText(strategy.get_default_music_prompt())
    def closeEvent(self, event):
        self.log_message("正在关闭应用程序...")
        self.stop_current_video_playback()
        if self.pipeline:
            self.pipeline.cleanup_temp_files()
        if self.thread and self.thread.isRunning():
            self.thread.quit()
            if not self.thread.wait(3000):
                self.log_message("工作线程未能及时关闭，将强制终止。")
                self.thread.terminate()
                self.thread.wait()
        self.log_message("应用程序已关闭。")
        event.accept()
if __name__ == "__main__":
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())