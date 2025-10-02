#pragma once
#include <QObject>
#include <QProcess>


class AppSettings;


class DaemonController : public QObject {
Q_OBJECT
public:
explicit DaemonController(AppSettings &settings, QObject *parent=nullptr);


bool isRunning() const;
void start();
void stop();


signals:
void started();
void stopped();
void logLine(const QString &line);


private:
AppSettings &m_settings;
QProcess m_proc;
};
