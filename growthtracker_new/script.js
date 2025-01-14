// API 配置
const API_BASE_URL = window.location.protocol === 'https:'
    ? 'https://api.snstracker.com'  // 生产环境，使用 HTTPS
    : 'http://api.snstracker.com';  // 本地开发环境

// DOM 元素
const linksInput = document.getElementById('linksInput');
const trackButton = document.getElementById('trackButton');
const resultsList = document.getElementById('resultsList');

// 历史记录管理
const HISTORY_KEY = 'sns_tracker_history';
const MAX_HISTORY_ITEMS = 100;

// 用户状态管理
const UserState = {
    isLoggedIn() {
        const token = localStorage.getItem('token');
        const tokenExpiry = localStorage.getItem('tokenExpiry');
        return token && tokenExpiry && new Date().getTime() < parseInt(tokenExpiry);
    },

    saveLoginInfo(token, email) {
        localStorage.setItem('token', token);
        localStorage.setItem('email', email);
        const expiry = new Date().getTime() + (24 * 60 * 60 * 1000);
        localStorage.setItem('tokenExpiry', expiry);
        localStorage.setItem('lastLoginTime', new Date().toISOString());
    },

    getLoginInfo() {
        return {
            token: localStorage.getItem('token'),
            email: localStorage.getItem('email'),
            lastLoginTime: localStorage.getItem('lastLoginTime'),
            tokenExpiry: localStorage.getItem('tokenExpiry')
        };
    },

    clearLoginInfo() {
        localStorage.removeItem('token');
        localStorage.removeItem('email');
        localStorage.removeItem('tokenExpiry');
        localStorage.removeItem('lastLoginTime');
    }
};

// 登录相关的API调用
const AuthAPI = {
    async login(email, password) {
        try {
            console.log('开始登录请求:', email);
            const response = await fetch(`${API_BASE_URL}/v1/account/auth`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ 
                    email: email, 
                    password: password 
                })
            });

            const result = await response.json();
            console.log('登录响应:', result);

            if (result.data && result.data.token) {
                return result.data.token;
            } else {
                throw new Error(result.message || '登录失败，请检查账号密码');
            }
        } catch (error) {
            console.error('登录错误:', error);
            if (error.name === 'TypeError' && error.message === 'Failed to fetch') {
                throw new Error('无法连接到服务器，请检查网络连接');
            }
            throw error;
        }
    },

    async refreshToken() {
        const { email } = UserState.getLoginInfo();
        if (!email) {
            throw new Error('未找到登录信息');
        }
        
        try {
            const token = await this.login(email, '');
            UserState.saveLoginInfo(token, email);
            return token;
        } catch (error) {
            UserState.clearLoginInfo();
            throw error;
        }
    }
};

// 添加 API 请求工具函数
const ApiClient = {
    async request(endpoint, options = {}) {
        const defaultOptions = {
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            credentials: 'include', // 包含 cookies
            mode: 'cors'           // 启用跨域
        };

        const token = UserState.getLoginInfo()?.token;
        if (token) {
            defaultOptions.headers['Authorization'] = `Bearer ${token}`;
        }

        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                ...defaultOptions,
                ...options,
                headers: {
                    ...defaultOptions.headers,
                    ...options.headers
                }
            });

            // 处理 HTTP 错误
            if (!response.ok) {
                if (response.status === 401) {
                    throw new Error('AUTH_ERROR');
                }
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `HTTP Error: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            if (error.message === 'AUTH_ERROR') {
                throw error;
            }
            if (!navigator.onLine) {
                throw new Error('网络连接已断开，请检查网络设置');
            }
            if (error.name === 'TypeError' && error.message === 'Failed to fetch') {
                throw new Error('无法连接到服务器，请检查网络连接或联系管理员');
            }
            throw error;
        }
    }
};

// 初始化登录功能
function initializeAuth() {
    const loginForm = document.getElementById('loginForm');
    const userInfo = document.getElementById('userInfo');
    const trackButton = document.getElementById('trackButton');

    // 登录表单提交
    const handleLogin = async (e) => {
        e.preventDefault();
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        
        try {
            console.log('尝试登录:', email);
            const token = await AuthAPI.login(email, password);
            console.log('获取到token:', token);
            UserState.saveLoginInfo(token, email);
            updateAuthUI();
        } catch (error) {
            console.error('登录处理错误:', error);
            alert(error.message || '登录失败，请稍后重试');
        }
    };

    // 绑定登录按钮点击事件
    loginForm.querySelector('.login-button').addEventListener('click', handleLogin);
    // 绑定表单提交事件
    loginForm.addEventListener('submit', handleLogin);

    // 退出登录
    document.querySelector('.logout-button').addEventListener('click', () => {
        UserState.clearLoginInfo();
        updateAuthUI();
    });

    // 更新UI显示
    function updateAuthUI() {
        if (UserState.isLoggedIn()) {
            const { email, lastLoginTime } = UserState.getLoginInfo();
            loginForm.style.display = 'none';
            userInfo.style.display = 'block';
            
            document.querySelector('.user-email').textContent = email;
            document.querySelector('.last-login-time').textContent = 
                new Date(lastLoginTime).toLocaleString();
            
            trackButton.disabled = false;
        } else {
            loginForm.style.display = 'block';
            userInfo.style.display = 'none';
            trackButton.disabled = true;
        }
    }

    // 初始检查登录状态
    updateAuthUI();
}

// 获取历史记录的键（针对不同用户）
function getHistoryKey() {
    return `${HISTORY_KEY}_${currentUser}`;
}

function saveToHistory(links, status, message) {
    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        
        const newRecord = {
            timestamp: new Date().toISOString(),
            links: links,
            status: status,
            message: message
        };
        
        history.unshift(newRecord);
        
        if (history.length > MAX_HISTORY_ITEMS) {
            history.length = MAX_HISTORY_ITEMS;
        }
        
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
        updateHistoryDisplay();
    } catch (error) {
        console.error('保存历史记录失败:', error);
    }
}

function updateHistoryDisplay() {
    const historyList = document.getElementById('historyList');
    if (!historyList) return;

    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        historyList.innerHTML = '';
        
        history.slice(0, MAX_HISTORY_ITEMS).forEach(record => {
            const item = document.createElement('div');
            item.className = 'history-item';
            
            const timestamp = new Date(record.timestamp).toLocaleString();
            const links = record.links.join('<br>');
            
            item.innerHTML = `
                <div class="history-time">${timestamp}</div>
                <div class="history-links">${links}</div>
                <div class="history-status ${record.status}">${record.message}</div>
            `;
            
            historyList.appendChild(item);
        });
    } catch (error) {
        console.error('更新历史记录显示失败:', error);
    }
}

// 检查链接是否在历史记录中
function checkDuplicateLinks(links) {
    try {
        const history = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        const historicalLinks = new Set(history.flatMap(record => record.links));
        
        return links.filter(link => historicalLinks.has(link));
    } catch (error) {
        console.error('检查重复链接失败:', error);
        return [];
    }
}

// 链接格式规则 - 移除严格验证
const LINK_RULES = {};

// 链接格式示例 - 移除格式限制
const FORMAT_EXAMPLES = {};

// 简化链接验证
function validateLink(link) {
    // 只检查链接是否为空
    if (!link.trim()) {
        return {
            valid: false,
            platform: null,
            message: "链接不能为空"
        };
    }

    return {
        valid: true,
        platform: 'unknown',
        message: "链接已接受"
    };
}

// 简化处理输入的链接函数
function processInputLinks(inputText) {
    const links = inputText
        .replace(/\r\n/g, '\n')
        .split(/[\n,\s]+/)
        .map(link => link.trim())
        .filter(link => link);

    // 只检查是否有空链接
    if (links.length === 0) {
        alert('请输入至少一个链接');
        return [];
    }

    return links;
}

// 添加实时验证
linksInput.addEventListener('input', debounce(function() {
    const links = this.value
        .split(/[\n,\s]+/)
        .map(link => link.trim())
        .filter(link => link);

    links.forEach(link => {
        const result = validateLink(link);
        if (!result.valid) {
            console.warn(`链接格式警告: ${link}\n${result.message}`);
        }
    });
}, 500));

// 防抖函数
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func.apply(this, args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// 获取新的 token
async function refreshToken() {
    try {
        const response = await fetch(`${API_BASE_URL}/v1/account/auth`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'accept': 'application/json'
            },
            body: JSON.stringify({
                email: "test@langoo.cc",
                password: "123456"
            })
        });

        if (!response.ok) {
            throw new Error('认证失败');
        }

        const data = await response.json();
        authToken = data.token;
        return true;
    } catch (error) {
        console.error('获取新token失败:', error);
        return false;
    }
}

// 添加 loading 状态控制
function setLoading(button, isLoading) {
    const spinner = button.querySelector('.loading-spinner');
    const text = button.querySelector('.button-text');
    
    button.disabled = isLoading;
    spinner.style.display = isLoading ? 'block' : 'none';
    text.style.opacity = isLoading ? '0' : '1';
    
    if (isLoading) {
        button.classList.add('loading');
    } else {
        button.classList.remove('loading');
    }
}

// 添加反馈动画
function showFeedback(element, type) {
    element.classList.add('feedback-animation', type);
    setTimeout(() => {
        element.classList.remove('feedback-animation', type);
    }, 300);
}

// 添加键盘导航支持
document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.ctrlKey) {
        const trackButton = document.getElementById('trackButton');
        if (!trackButton.disabled) {
            trackButton.click();
        }
    }
});

// 修改处理函数
async function handleTrackLinks() {
    const trackButton = document.getElementById('trackButton');
    setLoading(trackButton, true);
    
    try {
        // 检查登录状态
        if (!UserState.isLoggedIn()) {
            alert('请先登录');
            return;
        }

        const { token } = UserState.getLoginInfo();
        if (!token) {
            alert('登录已过期，请重新登录');
            UserState.clearLoginInfo();
            updateAuthUI();
            return;
        }

        // 获取并处理输入的链接
        const links = processInputLinks(linksInput.value);
        if (links.length === 0) {
            alert('请输入至少一个有效的链接');
            return;
        }

        // 检查重复链接
        const duplicates = checkDuplicateLinks(links);
        if (duplicates.length > 0) {
            const confirmMessage = `以下链接已经在历史记录中存在：\n\n${duplicates.join('\n')}\n\n是否继续添加？`;
            if (!confirm(confirmMessage)) {
                // 从链接列表中移除重复项
                const uniqueLinks = links.filter(link => !duplicates.includes(link));
                if (uniqueLinks.length === 0) {
                    return;
                }
                // 更新输入框中的链接
                linksInput.value = uniqueLinks.join('\n');
                // 继续处理剩余的链接
                return handleTrackLinks();
            }
        }

        // 更新输入框显示格式化后的链接
        linksInput.value = links.join('\n');

        // 清空结果列表
        resultsList.innerHTML = '';

        // 发送请求
        const response = await fetch(`${API_BASE_URL}/v1/track/feed`, {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                feed_urls: links
            })
        });

        if (!response.ok) {
            throw new Error(`请求失败: ${response.status}`);
        }

        // 处理成功
        links.forEach(link => {
            const item = createResultItem(link);
            resultsList.appendChild(item);
            updateResultStatus(item, 'success', '添加成功');
        });

        saveToHistory(links, 'success', '添加成功');
        showFeedback(resultsList, 'success');

    } catch (error) {
        console.error('操作失败:', error);
        
        let errorMessage = '添加失败';
        if (error.message.includes('Failed to fetch')) {
            errorMessage = '无法连接到服务器，请检查网络连接';
        } else {
            errorMessage = `添加失败: ${error.message}`;
        }

        links?.forEach(link => {
            const item = createResultItem(link);
            resultsList.appendChild(item);
            updateResultStatus(item, 'error', errorMessage);
        });

        saveToHistory(links || [], 'error', errorMessage);
        showFeedback(resultsList, 'error');
    } finally {
        setLoading(trackButton, false);
    }
}

// 创建结果项 DOM 元素
function createResultItem(link) {
    const item = document.createElement('div');
    item.className = 'result-item';
    item.innerHTML = `
        <div class="link">${escapeHtml(link)}</div>
        <div class="status pending">处理中...</div>
    `;
    return item;
}

// 更新结果状态
function updateResultStatus(element, status, message) {
    const statusElement = element.querySelector('.status');
    statusElement.className = `status ${status}`;
    statusElement.textContent = message;
}

// HTML 转义函数，防止 XSS 攻击
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// 绑定事件监听器
trackButton.addEventListener('click', handleTrackLinks);

// 添加快捷键支持：Ctrl/Cmd + Enter 触发添加
linksInput.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        handleTrackLinks();
    }
});

// 页面加载时初始化
window.addEventListener('load', () => {
    initializeAuth();
    updateHistoryDisplay();
});

// 添加触摸设备支持
if ('ontouchstart' in window) {
    document.body.classList.add('touch-device');
}

// 添加 ARIA 标签支持
function updateAriaStatus(message) {
    const statusElement = document.getElementById('aria-status');
    if (!statusElement) {
        const div = document.createElement('div');
        div.id = 'aria-status';
        div.setAttribute('role', 'status');
        div.setAttribute('aria-live', 'polite');
        div.style.position = 'absolute';
        div.style.width = '1px';
        div.style.height = '1px';
        div.style.padding = '0';
        div.style.margin = '-1px';
        div.style.overflow = 'hidden';
        div.style.clip = 'rect(0, 0, 0, 0)';
        div.style.whiteSpace = 'nowrap';
        div.style.border = '0';
        document.body.appendChild(div);
    }
    statusElement.textContent = message;
} 