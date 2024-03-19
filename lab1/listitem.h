#ifndef LISTITEM_H
#define LISTITEM_H

#include <QWidget>

namespace Ui {
class ListItem;
}

class ListItem : public QWidget
{
    Q_OBJECT

public:
    explicit ListItem(QString site, QString login_encrypted, QString password_encrypted, QWidget *parent = nullptr);
    ~ListItem();

// private slots:
//     void on_lineEdit_2_selectionChanged();

//     void on_lineEdit_2_editingFinished();

private slots:
    void on_copyLoginButton_clicked();

    void on_copyPasswordButton_clicked();

signals:
    void enterPinSignal(QString toEncryptLogOrPass);


private:
    Ui::ListItem *ui;
    QString pass_encr;
    QString log_encr;
};

#endif // LISTITEM_H
