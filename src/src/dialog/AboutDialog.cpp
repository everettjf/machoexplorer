//
//  Created by everettjf
//  Copyright © 2017 everettjf. All rights reserved.
//
#include "AboutDialog.h"
#include <QPushButton>
#include "ui_AboutDialog.h"
#include "src/base/AppInfo.h"
#include "src/utility/Utility.h"

AboutDialog::AboutDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AboutDialog)
{
    ui->setupUi(this);

    QPixmap img(":res/machoexplorer.png");
    img.scaled(QSize(128,128),Qt::KeepAspectRatio);
    ui->label->setPixmap(img);


    QString info = QString("MachOExplorer\n\n"
                           "v%1\n\n"
                           "App is written by everettjf\n\n"
                           "Icon is designed by wantline")
            .arg(AppInfo::Instance().GetAppVersion());

    ui->label_info->setText(info);
    auto *discordButton = new QPushButton(tr("Discord"), this);
    ui->horizontalLayout->insertWidget(0, discordButton);
    connect(discordButton, &QPushButton::clicked, this, [] {
        util::openURL("https://discord.gg/eGzEaP6TzR");
    });
}

AboutDialog::~AboutDialog()
{
    delete ui;
}

void AboutDialog::on_pushButton_clicked()
{
    this->close();
}

void AboutDialog::on_pushButton_everettjf_clicked()
{
    util::openURL("https://github.com/everettjf");
}

void AboutDialog::on_pushButton_project_clicked()
{
    util::openURL("https://github.com/everettjf/MachOExplorer");
}

void AboutDialog::on_pushButton_wantline_clicked()
{
    util::openURL("https://weibo.com/wantline");
}
