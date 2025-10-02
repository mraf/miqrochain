#pragma once
#include <QWidget>
class RpcClient;
class QTimer;


class OverviewWidget : public QWidget {
Q_OBJECT
public:
explicit OverviewWidget(RpcClient &rpc, QWidget *parent=nullptr);


private slots:
void refresh();


private:
RpcClient &m_rpc;
QTimer *m_timer{nullptr};
};
