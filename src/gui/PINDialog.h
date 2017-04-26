#ifndef PINDIALOG_H
#define PINDIALOG_H

#include <QDialog>

namespace Ui {
class PINDialog;
}

class PINDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PINDialog(QWidget *parent = 0);
    ~PINDialog();
    QString pin() const;

private:
    Ui::PINDialog *ui;
};

#endif // PINDIALOG_H
