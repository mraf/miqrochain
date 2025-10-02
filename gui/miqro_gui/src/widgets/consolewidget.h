#pragma once
#include <QWidget>
class RpcClient; class QPlainTextEdit; class QLineEdit;


class ConsoleWidget : public QWidget {
Q_OBJECT
public:
explicit ConsoleWidget(RpcClient &rpc, QWidget *parent=nullptr);
private:
RpcClient &m_rpc;
QPlainTextEdit *m_out{nullptr};
QLineEdit *m_method{nullptr};
QLineEdit *m_params{nullptr};
};
