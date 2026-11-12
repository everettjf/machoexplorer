//
// Created by everettjf
// Copyright © 2017 AtomSprout. All rights reserved.
//
#include "CheckUpdateDialog.h"
#include "ReleaseInfo.h"
#include "ui_CheckUpdateDialog.h"
#include <QDateTime>
#include <QNetworkReply>
#include <QSettings>
#include <QTimer>
#include "src/base/AppInfo.h"
#include "src/utility/Utility.h"

CheckUpdateDialog::CheckUpdateDialog(QWidget *parent) :
    QDialog(parent), ui(new Ui::CheckUpdateDialog)
{
    ui->setupUi(this);
    ui->label->setText(QString("Checking for updates…\nCurrent version: %1")
                      .arg(AppInfo::Instance().GetAppVersion()));
    manager = new QNetworkAccessManager(this);
    QSettings settings;
    const auto cachedBody = settings.value("updates/githubRelease").toByteArray();
    const auto checkedAt = settings.value("updates/checkedAt").toLongLong();
    const auto age = QDateTime::currentSecsSinceEpoch() - checkedAt;
    if (age >= 0 && age < 3600 && !ReleaseInfo::parse(cachedBody).version.isNull()) {
        showRelease(cachedBody);
        return;
    }
    request.setUrl(QUrl("https://api.github.com/repos/everettjf/MachOExplorer/releases/latest"));
    request.setRawHeader("Accept", "application/vnd.github+json");
    request.setRawHeader("User-Agent", "MachOExplorer-update-check");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    auto reply = manager->get(request);
    auto timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, &QNetworkReply::abort);
    timer->start(15000);
    // Bound the response even when a remote endpoint sends an unexpected body.
    connect(reply, &QNetworkReply::readyRead, this, [reply] {
        if (reply->bytesAvailable() > 1024 * 1024) reply->abort();
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, timer] {
        timer->stop();
        const auto status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        const auto body = reply->readAll();
        const bool valid = reply->error() == QNetworkReply::NoError && status == 200
            && body.size() <= 1024 * 1024 && !ReleaseInfo::parse(body).version.isNull();
        reply->deleteLater();
        if (!valid) {
            ui->label->setText("Unable to check for updates. You can still open GitHub Releases below.");
            return;
        }
        QSettings settings;
        settings.setValue("updates/githubRelease", body);
        settings.setValue("updates/checkedAt", QDateTime::currentSecsSinceEpoch());
        showRelease(body);
    });
}

CheckUpdateDialog::~CheckUpdateDialog() { delete ui; }

void CheckUpdateDialog::showRelease(const QByteArray &body)
{
    const auto release = ReleaseInfo::parse(body);
    downloadUrl = release.url.toString();
    const auto current = ReleaseInfo::parseVersion(AppInfo::Instance().GetAppVersion());
    if (current.isNull()) {
        ui->label->setText("This development version cannot be compared. Open GitHub Releases for available downloads.");
    } else if (QVersionNumber::compare(release.version, current) <= 0) {
        ui->label->setText(QString("You are up to date. Current version: v%1").arg(current.toString()));
    } else {
        ui->label->setText(QString("A new version is available.\nCurrent: v%1 · Latest: v%2")
                          .arg(current.toString(), release.version.toString()));
    }
}

void CheckUpdateDialog::gotoDownloadPage() { util::openURL(downloadUrl); }
void CheckUpdateDialog::on_pushButton_clicked() { gotoDownloadPage(); close(); }
void CheckUpdateDialog::on_pushButton_2_clicked() { close(); }
