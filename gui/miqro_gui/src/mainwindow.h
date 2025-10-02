#pragma once
#include <QMainWindow>
class AppSettings; class RpcClient; class DaemonController;


class MainWindow : public QMainWindow {
Q_OBJECT
public:
MainWindow(AppSettings &settings, QWidget *parent=nullptr);


private:
AppSettings &m_settings;
RpcClient *m_rpc{nullptr};
DaemonController *m_daemon{nullptr};
};
