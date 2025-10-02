#pragma once
#include <QWidget>
class RpcClient; class QTimer; class QLabel;


class MiningWidget : public QWidget {
Q_OBJECT
public:
explicit MiningWidget(RpcClient &rpc, QWidget *parent=nullptr);
private:
RpcClient &m_rpc;
QTimer *m_timer{nullptr};
QLabel *m_hash{nullptr};
QLabel *m_height{nullptr};
};
