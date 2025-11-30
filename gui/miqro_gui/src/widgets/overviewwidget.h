#pragma once
#include <QWidget>
class RpcClient;
class QTimer;
class QLabel;
class QTableWidget;

class OverviewWidget : public QWidget {
Q_OBJECT
public:
explicit OverviewWidget(RpcClient &rpc, QWidget *parent=nullptr);

private:
void refreshMempool();

RpcClient &m_rpc;
QTimer *m_timer{nullptr};
QLabel *m_status{nullptr};
QLabel *m_mempoolStats{nullptr};
QTableWidget *m_mempoolTable{nullptr};
};
