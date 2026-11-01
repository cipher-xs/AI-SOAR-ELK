
# 🛡️ AI-SOAR: 基于 ELK + LLM + RAG 的智能安全运营与自动化响应平台

> 一个融合了 **大语言模型 (LLM)** 与 **本地知识库 (RAG)** 的新一代安全编排、自动化与响应 (SOAR) 实战项目。

![ELK](https://img.shields.io/badge/ELK-7.17.10-blue)
![Python](https://img.shields.io/badge/Python-3.10+-green)
![LLM](https://img.shields.io/badge/LLM-DeepSeek-orange)
![RAG](https://img.shields.io/badge/RAG-FAISS-red)

## 📖 项目简介

传统的 SOAR 系统往往基于死板的阈值（如：1分钟内 SSH 失败 10 次即封禁 IP），这在复杂的企业内网环境中极易造成“误封”内网运维人员或测试脚本。

本项目基于 ELK 搭建日志底座，通过 Filebeat 与 Logstash 提取攻击特征；在告警触发时，不仅通过钉钉推送分级告警，更引入了 **大模型 (DeepSeek)** 与 **RAG 技术**。系统会自动检索企业内部的《应急响应 SOP 知识库》，让 AI 生成专业且符合企业内部规范的研判建议，并**智能决定是否执行 `iptables` 封禁**，实现真正的自适应防御。

## 🏗️ 核心架构

```text
攻击流量 (SSH爆破/SQL注入) 
   ↓
Nginx / auth.log / syslog
   ↓
Filebeat (日志采集) → Logstash (Grok解析与正则特征匹配)
   ↓
Elasticsearch (存储与检索)
   ↓
Python 脚本 (按频次分级：低/中/高危)
   ↓
[高危触发] → RAG 检索 (FAISS + SentenceTransformers)
   ↓
DeepSeek LLM (基于 SOP 进行智能研判)
   ↓
钉钉推送告警 + 智能 SOAR 响应 (真实攻击则封禁，误报则放行)
```

## ✨ 核心亮点

1. 多维日志采集：Filebeat 采集 Nginx、syslog、auth.log，Logstash 识别 UNION SELECT、Failed password 等特征。
2. 分级告警机制：按攻击频次自动划分低危、中危、高危，避免告警疲劳。
3. RAG 知识库赋能：利用 sentence-transformers 和 FAISS 本地向量数据库，检索企业内部安全 SOP，解决大模型“幻觉”问题，让 AI 建议有据可依。
4. 智能 SOAR 响应：根据 AI 研判的 JSON 结果动态执行动作，高危真实攻击自动调用 iptables 封禁，AI 判定为误报则智能放行（Skip Block），彻底杜绝误封。

## 🚀 快速开始

1. 启动 ELK 底座

```bash
sudo docker compose up -d
```

2. 安装 RAG 依赖 (建议使用纯 CPU 版，节约内存)

```bash
pip3 install torch --index-url https://download.pytorch.org/whl/cpu
pip3 install sentence-transformers faiss-cpu
```

3. 配置环境变量

将 alarm_no_pip.py 中的 DINGTALK_URL 与 DEEPSEEK_API_KEY 替换为你自己的配置。

4. 启动自动化告警服务

```bash
export HF_ENDPOINT=https://hf-mirror.com
nohup python3 -u alarm_no_pip.py > alarm.log 2>&1 &
```

## 📸 效果展示

(在这里插入你的截图，例如：)
screenshots/01_dashboard.png
screenshots/02_ai_judgment.png

## ⚠️ 免责声明

本项目仅用于安全技术研究与防御体系建设交流，请在授权的测试环境中使用。





