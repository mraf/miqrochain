#include <QApplication>
#include "mainwindow.h"
#include "appsettings.h"


int main(int argc, char **argv){
QApplication app(argc, argv);
AppSettings settings;
MainWindow w(settings);
w.resize(1100, 720);
w.show();
return app.exec();
}
