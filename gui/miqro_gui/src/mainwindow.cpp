#include "mainwindow.h"
#include "appsettings.h"
#include "rpcclient.h"
#include "daemoncontroller.h"


#include "widgets/overviewwidget.h"
#include "widgets/walletwidget.h"
#include "widgets/miningwidget.h"
#include "widgets/consolewidget.h"
#include "widgets/settingswidget.h"
#include "widgets/logswidget.h"


#include <QTabWidget>
#include <QStatusBar>


MainWindow::MainWindow(AppSettings &settings, QWidget *p)
: QMainWindow(p), m_settings(settings) {
setWindowTitle("Miqrochain Core");


m_rpc = new RpcClient(m_settings, this);
m_daemon = new DaemonController(m_settings, this);


auto *tabs = new QTabWidget();
tabs->addTab(new OverviewWidget(*m_rpc), "Overview");
tabs->addTab(new WalletWidget(*m_rpc), "Wallet");
tabs->addTab(new MiningWidget(*m_rpc), "Mining");
tabs->addTab(new ConsoleWidget(*m_rpc), "Console");
tabs->addTab(new SettingsWidget(m_settings, *m_daemon), "Settings");
tabs->addTab(new LogsWidget(*m_daemon), "Logs");
setCentralWidget(tabs);


statusBar()->showMessage("Ready");
}
