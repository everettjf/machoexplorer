// Copyright © 2026 AtomSprout. All rights reserved.
#pragma once
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QUrl>
#include <QVersionNumber>

struct ReleaseInfo {
    QVersionNumber version;
    QUrl url;

    static QVersionNumber parseVersion(QString value) {
        value = value.trimmed();
        if (value.startsWith('v')) value.remove(0, 1);
        // Published stable releases must use the same numeric version as the app.
        if (!QRegularExpression("^[0-9]+\\.[0-9]+\\.[0-9]+$").match(value).hasMatch()) return {};
        return QVersionNumber::fromString(value);
    }

    static ReleaseInfo parse(const QByteArray &body) {
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(body, &error);
        if (error.error != QJsonParseError::NoError || !document.isObject()) return {};
        const auto object = document.object();
        if (!object.value("draft").isBool() || !object.value("prerelease").isBool()
            || object.value("draft").toBool() || object.value("prerelease").toBool()) return {};
        ReleaseInfo result{parseVersion(object.value("tag_name").toString()),
                           QUrl(object.value("html_url").toString())};
        if (result.version.isNull() || result.url.scheme() != "https"
            || result.url.host() != "github.com" || result.url.port(-1) != -1 || !result.url.userInfo().isEmpty()
            || !result.url.path().startsWith("/everettjf/MachOExplorer/releases/tag/")
            || result.url.hasQuery() || result.url.hasFragment()) return {};
        return result;
    }
};
