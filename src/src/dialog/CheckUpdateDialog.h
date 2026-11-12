//
//  Created by everettjf
//  Copyright © 2017 AtomSprout. All rights reserved.
//
#ifndef CHECKUPDATEDIALOG_H
#define CHECKUPDATEDIALOG_H

#include <QDialog>
#include <QNetworkAccessManager>
#include <QNetworkRequest>


namespace Ui {
class CheckUpdateDialog;
}

class CheckUpdateDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CheckUpdateDialog(QWidget *parent = 0);
    ~CheckUpdateDialog();
    void gotoDownloadPage();

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    void showRelease(const QByteArray &body);
    QString downloadUrl = "https://github.com/everettjf/MachOExplorer/releases/latest";
    Ui::CheckUpdateDialog *ui;
    QNetworkAccessManager *manager;
    QNetworkRequest request;
};

#endif // CHECKUPDATEDIALOG_H
