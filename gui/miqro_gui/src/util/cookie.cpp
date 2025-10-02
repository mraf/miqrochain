#include "cookie.h"
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QProcessEnvironment>


namespace util {


QString defaultDataDir() {
#ifdef Q_OS_WIN
const auto appdata = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
// AppDataLocation is usually %APPDATA%/Company/App; we prefer bare %APPDATA%/miqrochain
QString base = QProcessEnvironment::systemEnvironment().value("APPDATA");
if (!base.isEmpty()) return QDir(base).filePath("miqrochain");
return QDir(appdata).filePath("miqrochain");
#else
QString home = QDir::homePath();
return QDir(home).filePath(".miqrochain");
#endif
}


QString defaultCookiePath() {
return QDir(defaultDataDir()).filePath(".cookie");
}


QString readCookieToken(QString *err) {
// 1) Prefer env MIQ_RPC_TOKEN
const auto env = QProcessEnvironment::systemEnvironment();
const QString envTok = env.value("MIQ_RPC_TOKEN");
if (!envTok.trimmed().isEmpty()) return envTok.trimmed();


// 2) Fallback to cookie file
const QString path = defaultCookiePath();
QFile f(path);
if (!f.exists()) { if (err) *err = QString("Cookie not found at %1").arg(path); return {}; }
if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) { if (err) *err = QString("Cannot open cookie at %1").arg(path); return {}; }
QTextStream ts(&f);
const QString line = ts.readLine();
if (line.trimmed().isEmpty()) { if (err) *err = QString("Cookie file empty at %1").arg(path); return {}; }
return line.trimmed();
}


}
