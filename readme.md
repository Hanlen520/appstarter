# 功能
- 批量安装并启动APP，触发APP尽可能多的功能
- 结合代理端的漏洞扫描功能，发现尽APP可能多的漏洞

# 使用
- pip install -r require.txt
- 设置手机wifi代理到被动扫描器
- Usage: python3 monkey.py -h
- 退出: Ctrl+C

# 原理
- 启动所有导出Activity/Service组件，并结合moneky点击
    
# ps
- 需要手机及电脑配有frida环境
- 需要开启USB调试、USB安装、USB调试(安全设置)
- 经过`小米系列手机`测试
- **防monkey点击导致断网等误点击，可以调整手机界面布局/增加点击深度: 顶部wifi放置最后/左下角电话、短信按钮移走**
- 解决难点：绕过部分MIUI的USB安装管理，实现自动安装APP；hook方式解决权限申请弹框；frida绕过APP的SSL证书校验；设备掉线检查