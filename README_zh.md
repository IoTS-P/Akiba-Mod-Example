**注意：请不要单独 clone 这个仓库，请使用下面的命令克隆整个 Akiba 项目：**

```shell
git clone https://github.com/IoTS-P/Akiba.git
cd Akiba
git submodule update --init --recursive
```

# Akiba 示例模块 ( Akiba Mod Example )

Akiba 示例模块包含一个简单的模块，用于获取一个二进制文件中的所有字符串值，并将这些值以 JSON 数组格式保存到数据库。

你可以在该模块基础上进行开发，替换 `AkibaExample.kt` 中的原有功能代码，并开发新的功能，而无需大幅修改 `build.gradle.kts` 等用于构建或项目配置的其他文件。

该模块依赖 `AkibaUtils` 模块。[链接](https://github.com/IoTS-P/Akiba-Mod-Utils)，在该模块仓库中，包含已经打包完成的 `AkibaUtils` Jar 文件（位于 modules）。

## 构建与测试运行

你需要克隆 `Akiba` 主仓库后拉取所有子仓库，随后使用 Gradle 构建：

```shell
./gradlew akiba_mod_example:moduleJar-AkibaModExample1
./gradlew akiba_mod_example:moduleJar-AkibaModExample2
```

构建得到的文件为 `build/libs/amod-AkibaModExample-<version>.jar`

构建好的 Jar 文件已经保存到 `Akiba` 主仓库的 `dockerfile-needed` 目录中，使用下面的命令启动 Docker 服务后，运行测试脚本即可导入一个示例二进制文件并启动本示例模块：

```shell
# 在 Akiba 主仓库根目录运行（需要安装 docker-compose-v2，不是 docker-compose！）
docker compose up --build

# 如果需要测试容器的主要功能，使用另一个终端运行下面的命令
docker exec -it akiba_app_1 /bin/bash
../binaries/test_run.sh
```

在一切正常的情况下，测试脚本将会测试：
- Akiba 框架与 Akiba 数据库守护程序的连接是否正常
- Akiba 框架能否正常运行模块
- Akiba 数据库守护程序能否正常进行数据库备份与恢复

后续可能会添加更多测试用例。