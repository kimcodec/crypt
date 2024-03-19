#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QLineEdit>
#include <QJsonArray>
#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    bool readJSON(unsigned char *key);
    QJsonArray jsonArr;
    void filterListWidget(const QString &searchStrings);
    static int decryptQByteArray(const QByteArray& encryptedBytes, QByteArray& decryptedBytes, unsigned char *key);
    ~MainWindow();

private:
    bool isAuthenticated = 0;
    Ui::MainWindow *ui;
    QString toEncryptLogOrPass;

public slots:
    void on_enterPinSignal(QString toEncryptLogOrPass);


private slots:
    void on_lineEdit_2_returnPressed();

};
#endif // MAINWINDOW_H
