import Dependencies._

// shadow sbt-scalajs' crossProject and CrossType until Scala.js 1.0.0 is released
import sbtcrossproject.crossProject

def v: String = "4.1.1-SNAPSHOT"

ThisBuild / version := v
ThisBuild / scalaVersion := scala213
ThisBuild / crossScalaVersions := Seq(scala211, scala212, scala213, scala3)
ThisBuild / scalafmtOnCompile := true

lazy val root = (project in file("."))
  .aggregate(scoptJS, scoptJVM, scoptNative)
  .settings(
    name := "scopt root",
    publish / skip := true,
    crossScalaVersions := Nil,
    commands += Command.command("release") { state =>
      "clean" ::
        "+publishSigned" ::
        state
    },
  )

lazy val scopt = (crossProject(JSPlatform, JVMPlatform, NativePlatform) in file("."))
  .settings(
    name := "scopt",
    // site
    // to preview, preview-site
    // to push, ghpages-push-site
    SiteScaladoc / siteSubdirName := s"$v/api",
    git.remoteRepo := "git@github.com:scopt/scopt.git",
    scalacOptions ++= Seq("-language:existentials", "-deprecation"),
    scalacOptions ++= {
      CrossVersion.partialVersion(scalaVersion.value) match {
        case Some((3, _)) =>
          Seq("-source:3.0-migration")
        case Some((2, v)) if v <= 12 =>
          Seq("-Xfuture")
        case _ =>
          Nil
      }
    },
    libraryDependencies += "com.eed3si9n.verify" %%% "verify" % verifyVersion % Test,
    testFrameworks += new TestFramework("verify.runner.Framework"),
    // libraryDependencies += "org.scalameta" %% "munit" % "0.7.20" % Test,
    // testFrameworks += new TestFramework("munit.Framework"),
    // scaladoc fix
    Compile / unmanagedClasspath += Attributed.blank(new java.io.File("doesnotexist"))
  )
  .platformsSettings(JVMPlatform, JSPlatform)(
    Seq(Compile, Test).map { x =>
      (x / unmanagedSourceDirectories) += {
        baseDirectory.value.getParentFile / s"jvm_js/src/${Defaults.nameForSrc(x.name)}/scala/"
      }
    },
  )
  .jsSettings(
    scalaJSLinkerConfig ~= (_.withModuleKind(ModuleKind.CommonJSModule)),
    scalacOptions += {
      val a = (LocalRootProject / baseDirectory).value.toURI.toString
      val g = "https://raw.githubusercontent.com/scopt/scopt/" + sys.process
        .Process("git rev-parse HEAD")
        .lineStream_!
        .head
      val key = CrossVersion.partialVersion(scalaVersion.value) match {
        case Some((3, _)) =>
          "-scalajs-mapSourceURI"
        case _ =>
          "-P:scalajs:mapSourceURI"
      }
      s"${key}:$a->$g/"
    },
  )

lazy val scoptJS = scopt.js

lazy val scoptJVM = scopt.jvm
  .enablePlugins(SiteScaladocPlugin)
  .enablePlugins(GhpagesPlugin)

lazy val scoptNative = scopt.native
