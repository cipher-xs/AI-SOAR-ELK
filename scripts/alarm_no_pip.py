import urllib.request
import urllib.error
import json
import time
import subprocess
import os
from datetime import datetime

# 导入 RAG 检索模块
from rag_helper import load_and_split_docs, build_index, retrieve_context

# ================= 配置区 =================
# 已经自动填入你的真实钉钉 Webhook
DINGTALK_URL = "https://oapi.dingtalk.com/robot/send?access_token=YOUR_DINGTALK_TOKEN"

ES_URL = "http://localhost:9200/secops-*/_search"
AUDIT_LOG = "/opt/secops-elk/scripts/audit.log"

# 已经自动填入你的真实 DeepSeek API Key
DEEPSEEK_API_KEY = "sk-YOUR_DEEPSEEK_API_KEY"
LLM_URL = "https://api.deepseek.com/chat/completions"

# 大模型系统提示词
SYSTEM_PROMPT = """你是一名资深安全分析师。请根据提供的日志证据和内部安全SOP，对安全告警进行研判。
请严格以 JSON 格式输出，不要输出任何额外的 Markdown 标记，字段定义如下：
{
  "is_false_positive": true, 
  "severity_reassessed": "High",
  "risk_summary": "用一句话概括攻击意图和风险",
  "recommended_actions": ["动作1", "动作2"]
}
请严格基于证据判断，不要臆测。"""

# 告警分级阈值
LEVEL_LOW = 5     # 低危：5-9 次
LEVEL_MID = 10    # 中危：10-19 次
LEVEL_HIGH = 20   # 高危：>=10 次，触发 AI 研判和封禁

# 白名单：永不封禁这些 IP
WHITELIST = { "localhost", "192.168.220.132", "192.168.220.1", "127.0.0.1" }

# 冷却时间：同一 IP 10 分钟内只告警一次
COOLDOWN_SECONDS = 600

last_alert_time = {}

# 全局 RAG 变量
rag_index = None
rag_docs = None
# ==========================================


def audit_log(action, ip, detail):
    """写入审计日志"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] [{action}] IP={ip} {detail}\n"
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(line)
    print(line.strip())


def analyze_with_llm(alert_context):
    """调用大模型分析告警（结合 RAG 检索内部 SOP）"""
    global rag_index, rag_docs
    
    # 1. 使用告警上下文作为查询，从 SOP 中检索相关段落
    retrieved = retrieve_context(alert_context, rag_index, rag_docs, k=2)
    rag_context = "\n\n".join(retrieved)
    print(f"[*] RAG 检索到 {len(retrieved)} 个相关文档块。")

    # 2. 将检索结果和告警上下文一起放入 Prompt
    enhanced_prompt = f"""请严格依据以下【内部安全标准操作流程（SOP）】，对安全告警进行研判。

【相关SOP内容】
{rag_context}

【告警上下文】
{alert_context}

请以 JSON 格式输出：
{{
  "is_false_positive": true,
  "severity_reassessed": "High",
  "risk_summary": "概括",
  "recommended_actions": ["动作1", "动作2"]
}}
"""
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek-chat",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": enhanced_prompt}
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"} 
    }
    
    req = urllib.request.Request(
        LLM_URL, 
        data=json.dumps(payload).encode('utf-8'), 
        headers=headers, 
        method='POST'
    )
    
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))
            content = result["choices"][0]["message"]["content"]
            return json.loads(content)
    except Exception as e:
        print(f"[-] LLM 分析失败: {e}")
        return None


def send_dingtalk_alert(text, level):
    """发送钉钉告警"""
    emoji = {"低危": "🟡", "中危": "🟠", "高危": "🔴"}.get(level, "⚪")
    headers = {"Content-Type": "application/json"}
    data = {
        "msgtype": "markdown",
        "markdown": {
            "title": f"{emoji} {level}：SSH暴力破解告警",
            "text": f"**【安全告警】{emoji} {level}**\n\n{text}\n\n请立即排查！"
        }
    }
    req = urllib.request.Request(
        DINGTALK_URL,
        data=json.dumps(data).encode('utf-8'),
        headers=headers,
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            print(f"[+] 钉钉告警发送成功，状态码: {response.status}")
    except Exception as e:
        print(f"[-] 钉钉告警发送失败: {e}")


def block_ip(ip):
    """调用 iptables 封禁 IP"""
    if ip in WHITELIST:
        audit_log("SKIP", ip, "命中白名单，跳过封禁")
        return

    try:
        check = subprocess.run(
            ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5
        )
        if check.returncode == 0:
            audit_log("SKIP", ip, "IP 已被封禁，跳过")
            return
    except Exception:
        pass

    try:
        subprocess.run(
            ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, timeout=5
        )
        audit_log("BLOCK", ip, "已通过 iptables 封禁")
    except Exception as e:
        audit_log("BLOCK_FAIL", ip, f"封禁失败: {e}")


def check_ssh_bruteforce():
    """查询 ES，检测 SSH 暴力破解，按攻击源 IP 聚合"""
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match_phrase": {"message": "Failed password"}},
                    {"range": {"@timestamp": {"gte": "now-1m"}}}
                ]
            }
        },
        "size": 0,
        "aggs": {
            "by_src_ip": {
                "terms": {
                    "field": "src_ip.keyword",
                    "size": 20
                }
            }
        }
    }

    try:
        req = urllib.request.Request(
            ES_URL,
            data=json.dumps(query).encode('utf-8'),
            headers={"Content-Type": "application/json"},
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode('utf-8'))
            buckets = result.get("aggregations", {}).get("by_src_ip", {}).get("buckets", [])
            if not buckets:
                print("[*] 最近1分钟无 SSH 失败记录")
                return
                
            for b in buckets:
                ip = b["key"]
                count = b["doc_count"]
                print(f"[*] 攻击源 IP: {ip}, 失败次数: {count}")

                if count >= LEVEL_HIGH:
                    level = "高危"
                elif count >= LEVEL_MID:
                    level = "中危"
                elif count >= LEVEL_LOW:
                    level = "低危"
                else:
                    continue

                now = time.time()
                if now - last_alert_time.get(ip, 0) < COOLDOWN_SECONDS:
                    print(f"[-] {ip} 告警冷却中，跳过")
                    continue

                msg = f"**攻击源IP:** {ip}\n**1分钟内失败次数:** {count} 次\n**级别:** {level}"
                
                ai_analysis = None
                if level == "高危":
                    print(f"[*] 触发高危告警，正在请求 AI 研判...")
                    alert_context = f"告警类型: SSH暴力破解\n攻击源IP: {ip}\n1分钟内失败次数: {count}"
                    ai_analysis = analyze_with_llm(alert_context)
                    
                    if ai_analysis:
                        print(f"[+] AI 研判完成: {ai_analysis}")
                        ai_msg = f"\n\n**🤖 AI 研判:**\n- 误报可能性: {ai_analysis.get('is_false_positive')}\n- 严重等级: {ai_analysis.get('severity_reassessed')}\n- 意图: {ai_analysis.get('risk_summary')}\n- 建议: {', '.join(ai_analysis.get('recommended_actions', []))}"
                        msg += ai_msg
                    else:
                        msg += "\n\n*(AI 研判超时或无响应)*"

                send_dingtalk_alert(msg, level)
                audit_log("ALERT", ip, f"级别={level}, 次数={count}")
                last_alert_time[ip] = now

                if count >= LEVEL_HIGH:
                    should_block = True
                    if ai_analysis and ai_analysis.get("is_false_positive") is True:
                        should_block = False
                        print(f"[-] AI 判定为误报，取消封禁动作！")
                        audit_log("SKIP", ip, "AI判定为误报，跳过封禁")
                    
                    if should_block:
                        block_ip(ip)

    except Exception as e:
        print(f"[-] 查询 Elasticsearch 失败: {e}")


if __name__ == "__main__":
    # 初始化 RAG 知识库
    print("[+] 正在加载安全知识库...")
    try:
        kb_docs = load_and_split_docs("/opt/secops-elk/scripts/knowledge_base/")
        rag_index, rag_docs = build_index(kb_docs)
        print(f"[+] 知识库加载完成，共 {len(rag_docs)} 个文本块。")
    except Exception as e:
        print(f"[-] 知识库加载失败: {e}")
        exit(1)
    
    print("[+] 安全告警脚本已启动，正在监听 ES 日志...")
    print(f"[+] 告警阈值: 低危>={LEVEL_LOW}, 中危>={LEVEL_MID}, 高危>={LEVEL_HIGH}")
    print(f"[+] 白名单: {WHITELIST}")
    while True:
        check_ssh_bruteforce()
        time.sleep(60)
