#pragma once
#include <QWidget>
class AppSettings; class DaemonController; class QLineEdit; class QCheckBox;


class SettingsWidget : public QWidget {
Q_OBJECT
public:
explicit SettingsWidget(AppSettings &settings, DaemonController &daemon, QWidget *parent=nullptr);
private:
AppSettings &m_settings;
DaemonController &m_daemon;
QLineEdit *m_rpcUrl{nullptr};
QLineEdit *m_daemonPath{nullptr};
QLineEdit *m_confPath{nullptr};
QCheckBox *m_autoCookie{nullptr};
QLineEdit *m_manualToken{nullptr};
};
