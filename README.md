# 运行介绍
### 这是一个小学期实训作业，基于flask框架,完成了一个网吧管理系统。
# 部署：
### 安装所需的库，
``` 
pip install Flask
pip install Flask-SQLAlchemy
```
运行```app.py```即可
## TODO List

### 呼叫管理员功能

- **添加“备注”功能:** 允许用户在呼叫管理员时，添加备注信息，方便管理员及时了解用户需求。

### 用户注册功能

- **采用管理员提供的密钥:** 允许用户自行设置密码，简化注册流程。

### 充值功能

- **接入 API 接口:** 条件允许的情况下，使用 API 接口实现充值功能，以便与实际充值系统进行对接。

### 控制模块

- **开发控制模块:** 实现用户未登录时无法访问网络和使用电脑的功能，确保网络安全和资源管理。

### 其他

- **完善用户界面:** 优化用户界面设计，提升用户体验。
- **添加日志记录功能:** 记录系统操作日志，便于问题排查和系统维护。
- **测试和调试:** 完善测试用例，进行系统测试和调试，确保系统稳定运行。
# 运行样图
![控制面板](images/login.png)
![控制面板](images/screen10.png)
![控制面板](images/admin1.png)
![图片](images/admin2.png)

