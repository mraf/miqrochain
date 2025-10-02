#pragma once
#include <QString>


namespace util {


QString defaultDataDir(); // OS‑specific (~/.miqrochain or %APPDATA%\miqrochain)
QString defaultCookiePath(); // dataDir + ".cookie"
QString readCookieToken(QString *err); // returns token or empty; sets err on failure


}
