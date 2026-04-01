**Note: Please do not clone this repository separately. Use the following command to clone the entire Akiba project:**

```shell
git clone https://github.com/IoTS-P/Akiba.git
cd Akiba
git submodule update --init --recursive
```

# Akiba Example Module ( Akiba Mod Example )

The Akiba Example Module contains a simple module that retrieves all string values from a binary file and saves these values as a JSON array to a database.

You can develop based on this module by replacing the original functionality code in `AkibaExample.kt` and developing new features without significantly modifying other files such as `build.gradle.kts` used for building or project configuration.

This module depends on the `AkibaUtils` module. [Link](https://github.com/IoTS-P/Akiba-Mod-Utils). In that module's repository, you'll find the packaged `AkibaUtils` JAR file (located in modules).

## Build and Test Run

You need to clone the `Akiba` main repository and pull all submodules, then build using Gradle:

```shell
./gradlew akiba_mod_example:moduleJar-AkibaModExample1
./gradlew akiba_mod_example:moduleJar-AkibaModExample2
```

The built file will be `build/libs/amod-AkibaModExample-<version>.jar`

The built JAR file has been saved to the `dockerfile-needed` directory of the `Akiba` main repository. After starting the Docker service using the command below, run the test script:

```shell
# Run in the root directory of Akiba main repository (requires docker-compose-v2, not docker-compose!)
docker compose up --build

# If you need to test the container's functionality, run the following command in another terminal
docker exec -it akiba_app_1 /bin/bash
../binaries/test_run.sh
```

Under normal circumstances, the test script will test:
- Whether the connection between Akiba Framework and Akiba Database Daemon works properly
- Whether Akiba Framework can execute modules correctly
- Whether Akiba Database Daemon can perform database backup and restore correctly

More test cases may be added in the future.