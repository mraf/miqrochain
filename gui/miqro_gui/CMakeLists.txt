cmake_minimum_required(VERSION 3.22)
project(miqro_gui LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)


set(SRC
src/main.cpp
src/appsettings.h src/appsettings.cpp
src/rpcclient.h src/rpcclient.cpp
src/daemoncontroller.h src/daemoncontroller.cpp
src/mainwindow.h src/mainwindow.cpp
src/widgets/overviewwidget.h src/widgets/overviewwidget.cpp
src/widgets/walletwidget.h src/widgets/walletwidget.cpp
src/widgets/miningwidget.h src/widgets/miningwidget.cpp
src/widgets/consolewidget.h src/widgets/consolewidget.cpp
src/widgets/settingswidget.h src/widgets/settingswidget.cpp
src/widgets/logswidget.h src/widgets/logswidget.cpp
src/util/cookie.h src/util/cookie.cpp
resources/icons.qrc
)


find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Network Core Gui)
qt_add_executable(miqro-gui ${SRC})
target_link_libraries(miqro-gui PRIVATE Qt6::Widgets Qt6::Network Qt6::Core Qt6::Gui)


# Windows nice icon / app details
if (WIN32)
set_property(TARGET miqro-gui PROPERTY WIN32_EXECUTABLE TRUE)
endif()


# Safer warnings
if (MSVC)
target_compile_options(miqro-gui PRIVATE /W4 /permissive-)
else()
target_compile_options(miqro-gui PRIVATE -Wall -Wextra -Wpedantic)
endif()
