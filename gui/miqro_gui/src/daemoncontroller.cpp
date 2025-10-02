#include "daemoncontroller.h"
#include "appsettings.h"
#include <QFileInfo>
#include <QDir>


DaemonController::DaemonController(AppSettings &s, QObject *p)
: QObject(p), m_settings(s) {
QObject::connect(&m_proc, &QProcess::readyReadStandardOutput, this, [this]{
emit logLine(QString::fromUtf8(m_proc.readAllStandardOutput()));
});
QObject::connect(&m_proc, &QProcess::readyReadStandardError, this, [this]{
emit logLine(QString::fromUtf8(m_proc.readAllStandardError()));
});
QObject::connect(&m_proc, QOverload<int,QProcess::ExitStatus>::of(&QProcess::finished), this, [this](int, QProcess::ExitStatus){ emit stopped(); });
}


bool DaemonController::isRunning() const { return m_proc.state() != QProcess::NotRunning; }


void DaemonController::start(){
if (isRunning()) return;
QString exe = m_settings.daemonPath();
if (exe.isEmpty()) return;


QStringList args;
if (!m_settings.confPath().isEmpty()) {
args << "--conf" << m_settings.confPath();
}


m_proc.setProgram(exe);
m_proc.setArguments(args);
m_proc.start();
if (m_proc.waitForStarted(5000)) emit started();
}


void DaemonController::stop(){
if (!isRunning()) return;
m_proc.terminate();
if (!m_proc.waitForFinished(5000)) m_proc.kill();
}
