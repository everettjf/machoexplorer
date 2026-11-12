// Copyright © 2026 AtomSprout. All rights reserved.
#include "../../src/src/dialog/ReleaseInfo.h"
#include <QCoreApplication>
#include <QJsonArray>
#include <cstdio>

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    int failures = 0;
    auto check = [&](bool ok, const char *name) { if (!ok) { std::fprintf(stderr,"FAIL: %s\n",name); ++failures; } };
    auto release = [](QString tag, QString url = "https://github.com/everettjf/MachOExplorer/releases/tag/v2.0.16") {
        return QJsonDocument(QJsonObject{{"tag_name",tag},{"html_url",url},{"draft",false},{"prerelease",false}}).toJson();
    };
    const auto info = ReleaseInfo::parse(release("v2.0.16"));
    check(!info.version.isNull(), "stable GitHub response");
    check(QVersionNumber::compare(info.version,ReleaseInfo::parseVersion("2.0.9"))>0,"numeric ordering");
    check(QVersionNumber::compare(info.version,ReleaseInfo::parseVersion("2.0.17"))<0,"newer local build");
    check(ReleaseInfo::parseVersion(" v2.0.16\n")==info.version,"trim and prefix");
    for (const auto &tag : {"", "v2.0.16-beta", "2.0.16evil", "version2.0.16", "2.0"})
        check(ReleaseInfo::parse(release(tag)).version.isNull(),"malformed or prerelease tag");
    for (const auto &url : {"http://github.com/everettjf/MachOExplorer/releases/tag/v2.0.16", "https://evil.test/download", "https://github.com/other/project/releases/tag/v2.0.16", "https://github.com:4444/everettjf/MachOExplorer/releases/tag/v2.0.16"})
        check(ReleaseInfo::parse(release("v2.0.16",url)).version.isNull(),"untrusted release URL");
    check(ReleaseInfo::parse("not json").version.isNull(),"invalid JSON");
    check(ReleaseInfo::parse("[]").version.isNull(),"unexpected JSON shape");
    check(ReleaseInfo::parse("{\"message\":\"rate limited\"}").version.isNull(),"API error body");
    for (const auto &field : {"draft","prerelease"}) {
        auto object = QJsonDocument::fromJson(release("v2.0.16")).object();
        object[field] = true;
        check(ReleaseInfo::parse(QJsonDocument(object).toJson()).version.isNull(),"unpublished release");
    }
    return failures ? 1 : 0;
}
