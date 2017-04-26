#include "PINDialog.h"
#include "ui_PINDialog.h"

PINDialog::PINDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PINDialog)
{
    ui->setupUi(this);
    ui->pinEdit->setValidator(new QIntValidator(0, 9999, this));
}

PINDialog::~PINDialog()
{
    delete ui;
}

QString PINDialog::pin() const
{
    return ui->pinEdit->text();
}
