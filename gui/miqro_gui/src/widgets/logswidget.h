#pragma once
#include <QWidget>
class DaemonController; class QPlainTextEdit; class QPushButton;


class LogsWidget : public QWidget {
Q_OBJECT
public:
explicit LogsWidget(DaemonController &daemon, QWidget *parent=nullptr);
private:
QPlainTextEdit *m_out{nullptr};
};
