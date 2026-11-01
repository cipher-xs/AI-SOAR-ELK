import os
os.environ["TRANSFORMERS_NO_TF"] = "1" # 强制禁用 TensorFlow 以节省内存

import faiss
from sentence_transformers import SentenceTransformer

# 1. 初始化 Embedding 模型
model = SentenceTransformer('all-MiniLM-L6-v2')

# 2. 原生文本切分函数（替代 langchain）
def split_text(text, chunk_size=300, overlap=50):
    """按固定字符长度切分文本，保留重叠部分防止上下文断裂"""
    chunks = []
    start = 0
    text_length = len(text)
    
    while start < text_length:
        end = min(start + chunk_size, text_length)
        chunks.append(text[start:end])
        if end == text_length:
            break
        start += chunk_size - overlap
    return chunks

# 3. 加载并切分文档
def load_and_split_docs(kb_dir):
    docs = []
    if not os.path.exists(kb_dir):
        print(f"[-] 目录不存在: {kb_dir}")
        return docs
        
    for filename in os.listdir(kb_dir):
        if filename.endswith('.txt') or filename.endswith('.md'):
            with open(os.path.join(kb_dir, filename), 'r', encoding='utf-8') as f:
                content = f.read()
                # 使用原生切分函数
                chunks = split_text(content)
                docs.extend(chunks)
    return docs

# 4. 构建向量索引
def build_index(docs):
    if not docs:
        return None, []
    embeddings = model.encode(docs, show_progress_bar=True)
    dimension = embeddings.shape[1]
    index = faiss.IndexFlatL2(dimension)
    index.add(embeddings)
    return index, docs

# 5. 检索相关段落
def retrieve_context(query, index, docs, k=2):
    if not index or not docs:
        return []
    # 确保 k 不会大于实际文档数量
    k = min(k, len(docs))
    query_vec = model.encode([query])
    distances, indices = index.search(query_vec, k)
    return [docs[i] for i in indices[0]]
