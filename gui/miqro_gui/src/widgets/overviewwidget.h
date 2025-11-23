#pragma once
#include <QWidget>
class RpcClient;
class QTimer;
class QLabel;

class OverviewWidget : public QWidget {
Q_OBJECT
public:
explicit OverviewWidget(RpcClient &rpc, QWidget *parent=nullptr);

private:
RpcClient &m_rpc;
QTimer *m_timer{nullptr};
QLabel *m_status{nullptr};
};
