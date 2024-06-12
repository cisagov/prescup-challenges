
// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

use anyhow::Context;
use axum::{
    extract::Path,
    routing::{get, put},
    Extension, Json, Router,
};
use axum_macros::debug_handler;
use sqlx::{postgres::PgPoolOptions, query, query_as, query_file, query_file_as, PgPool};

mod airlock;
mod camera;
mod communication;
mod door;
mod environment;
mod error;
mod hydroponics;
mod power;

use self::airlock::{Airlock, AirlockFields};
use self::camera::{Camera, CameraFields};
use self::communication::CommunicationFields;
use self::door::DoorFields;
use self::environment::EnvironmentFields;
use self::error::Error;
use self::hydroponics::HydroponicsFields;
use self::power::PowerFields;

#[debug_handler]
async fn list_airlocks(db: Extension<PgPool>) -> Result<Json<Vec<AirlockFields>>, Error> {
    let airlocks = query_as!(AirlockFields, "SELECT * FROM airlock_controls")
        .fetch_all(&*db)
        .await?;

    Ok(Json(airlocks))
}

#[debug_handler]
async fn get_airlock(
    db: Extension<PgPool>,
    Path(airlock_id): Path<String>,
) -> Result<Json<AirlockFields>, Error> {
    let airlock_fields = query_file_as!(AirlockFields, "queries/get_airlock.sql", airlock_id)
        .fetch_one(&*db)
        .await?;

    Ok(Json(airlock_fields))
}

enum CycleDirection {
    Inward,
    Outward,
}

async fn cycle_airlock(
    db: Extension<PgPool>,
    Path(airlock_id): Path<String>,
    cycle_direction: CycleDirection,
) -> Result<Json<AirlockFields>, Error> {
    let airlock_fields = query_file_as!(AirlockFields, "queries/get_airlock.sql", airlock_id)
        .fetch_one(&*db)
        .await?;

    let mut airlock = Airlock::from(airlock_fields);
    if let Err(e) = match cycle_direction {
        CycleDirection::Inward => airlock.cycle_inward(),
        CycleDirection::Outward => airlock.cycle_outward(),
    } {
        return Err(Error::Anyhow(anyhow::Error::msg(e.error_msg)));
    }

    let airlock_fields = AirlockFields::from(airlock);

    query_file!(
        "queries/update_airlock.sql",
        airlock_fields.id,
        airlock_fields.outer_open,
        airlock_fields.inner_open,
        airlock_fields.pressurized
    )
    .execute(&*db)
    .await?;

    Ok(Json(airlock_fields))
}

#[debug_handler]
async fn list_cameras(db: Extension<PgPool>) -> Result<Json<Vec<CameraFields>>, Error> {
    let cameras = query_as!(CameraFields, "SELECT * FROM camera_controls")
        .fetch_all(&*db)
        .await?;

    Ok(Json(cameras))
}

#[debug_handler]
async fn get_camera(
    db: Extension<PgPool>,
    Path(camera_id): Path<String>,
) -> Result<Json<CameraFields>, Error> {
    let camera_fields = query_file_as!(CameraFields, "queries/get_camera.sql", camera_id)
        .fetch_one(&*db)
        .await?;

    Ok(Json(camera_fields))
}

enum CameraAction {
    StartRecording,
    StopRecording,
    Activate,
    Deactivate,
}

async fn camera_action(
    db: Extension<PgPool>,
    Path(camera_id): Path<String>,
    action: CameraAction,
) -> Result<Json<CameraFields>, Error> {
    let camera_fields = query_file_as!(CameraFields, "queries/get_camera.sql", camera_id)
        .fetch_one(&*db)
        .await?;

    let mut camera = Camera::from(camera_fields);
    if let Err(e) = match action {
        CameraAction::StartRecording => camera.start_recording(),
        CameraAction::StopRecording => camera.stop_recording(),
        CameraAction::Activate => camera.activate(),
        CameraAction::Deactivate => camera.deactivate(),
    } {
        return Err(Error::Anyhow(anyhow::Error::msg(e.error_msg)));
    }

    let camera_fields = CameraFields::from(camera);

    query_file!(
        "queries/update_camera.sql",
        camera_fields.id,
        camera_fields.active,
        camera_fields.recording,
    )
    .execute(&*db)
    .await?;

    Ok(Json(camera_fields))
}

#[debug_handler]
async fn list_communications(
    db: Extension<PgPool>,
) -> Result<Json<Vec<CommunicationFields>>, Error> {
    let communications = query_as!(CommunicationFields, "SELECT * FROM comm_controls")
        .fetch_all(&*db)
        .await?;

    Ok(Json(communications))
}

enum CommonAction {
    Activate,
    Deactivate,
    Toggle,
    Report,
}

async fn comm_action(
    db: Extension<PgPool>,
    Path(communication_id): Path<String>,
    action: CommonAction,
) -> Result<Json<CommunicationFields>, Error> {
    let mut comm_fields = query_as!(
        CommunicationFields,
        "SELECT * FROM comm_controls WHERE id = $1",
        communication_id
    )
    .fetch_one(&*db)
    .await?;

    comm_fields.active = match action {
        CommonAction::Report => return Ok(Json(comm_fields)),
        CommonAction::Activate => true,
        CommonAction::Deactivate => false,
        CommonAction::Toggle => !comm_fields.active,
    };

    query!(
        "UPDATE comm_controls SET active = $2 WHERE id = $1",
        comm_fields.id,
        comm_fields.active,
    )
    .execute(&*db)
    .await?;

    Ok(Json(comm_fields))
}

#[debug_handler]
async fn list_doors(db: Extension<PgPool>) -> Result<Json<Vec<DoorFields>>, Error> {
    let doors = query_as!(DoorFields, "SELECT * FROM door_controls")
        .fetch_all(&*db)
        .await?;

    Ok(Json(doors))
}

enum DoorAction {
    Open,
    Close,
    Toggle,
    Report,
}

async fn door_action(
    db: Extension<PgPool>,
    Path(door_id): Path<String>,
    action: DoorAction,
) -> Result<Json<DoorFields>, Error> {
    let mut door_fields = query_as!(
        DoorFields,
        "SELECT * FROM door_controls WHERE id = $1",
        door_id
    )
    .fetch_one(&*db)
    .await?;

    door_fields.open = match action {
        DoorAction::Report => return Ok(Json(door_fields)),
        DoorAction::Open => true,
        DoorAction::Close => false,
        DoorAction::Toggle => !door_fields.open,
    };

    query!(
        "UPDATE door_controls SET open = $2 WHERE id = $1",
        door_fields.id,
        door_fields.open,
    )
    .execute(&*db)
    .await?;

    Ok(Json(door_fields))
}

#[debug_handler]
async fn list_environments(db: Extension<PgPool>) -> Result<Json<Vec<EnvironmentFields>>, Error> {
    let environments = query_as!(EnvironmentFields, "SELECT * FROM environment_controls")
        .fetch_all(&*db)
        .await?;

    Ok(Json(environments))
}

#[debug_handler]
async fn list_hydroponics(db: Extension<PgPool>) -> Result<Json<Vec<HydroponicsFields>>, Error> {
    let hydroponics = query_as!(HydroponicsFields, "SELECT * FROM hydroponics_controls")
        .fetch_all(&*db)
        .await?;

    Ok(Json(hydroponics))
}

async fn hydroponics_action(
    db: Extension<PgPool>,
    Path(hydroponics_id): Path<String>,
    action: CommonAction,
) -> Result<Json<HydroponicsFields>, Error> {
    let mut hydroponics_fields = query_as!(
        HydroponicsFields,
        "SELECT * FROM hydroponics_controls WHERE id = $1",
        hydroponics_id
    )
    .fetch_one(&*db)
    .await?;

    hydroponics_fields.active = match action {
        CommonAction::Report => return Ok(Json(hydroponics_fields)),
        CommonAction::Activate => true,
        CommonAction::Deactivate => false,
        CommonAction::Toggle => !hydroponics_fields.active,
    };

    query!(
        "UPDATE hydroponics_controls SET active = $2 WHERE id = $1",
        hydroponics_fields.id,
        hydroponics_fields.active,
    )
    .execute(&*db)
    .await?;

    Ok(Json(hydroponics_fields))
}

#[debug_handler]
async fn list_power(db: Extension<PgPool>) -> Result<Json<Vec<PowerFields>>, Error> {
    let power = query_as!(PowerFields, "SELECT * FROM power_controls")
        .fetch_all(&*db)
        .await?;

    Ok(Json(power))
}

fn airlock_router() -> Router {
    Router::new()
        .route("/airlocks", get(list_airlocks))
        .route("/airlocks/:airlock_id", get(get_airlock))
        .route(
            "/airlocks/:airlock_id/cycle_outward",
            put(|db, airlock_id| cycle_airlock(db, airlock_id, CycleDirection::Outward)),
        )
        .route(
            "/airlocks/:airlock_id/cycle_inward",
            put(|db, airlock_id| cycle_airlock(db, airlock_id, CycleDirection::Inward)),
        )
}

fn camera_router() -> Router {
    Router::new()
        .route("/cameras", get(list_cameras))
        .route("/cameras/:camera_id", get(get_camera))
        .route(
            "/cameras/:camera_id/start_recording",
            put(|db, camera_id| camera_action(db, camera_id, CameraAction::StartRecording)),
        )
        .route(
            "/cameras/:camera_id/stop_recording",
            put(|db, camera_id| camera_action(db, camera_id, CameraAction::StopRecording)),
        )
        .route(
            "/cameras/:camera_id/activate",
            put(|db, camera_id| camera_action(db, camera_id, CameraAction::Activate)),
        )
        .route(
            "/cameras/:camera_id/deactivate",
            put(|db, camera_id| camera_action(db, camera_id, CameraAction::Deactivate)),
        )
}

fn comms_router() -> Router {
    Router::new()
        .route("/comms", get(list_communications))
        .route(
            "/comms/:comm_id",
            get(|db, comm_id| comm_action(db, comm_id, CommonAction::Report)),
        )
        .route(
            "/comms/:comm_id/activate",
            put(|db, comm_id| comm_action(db, comm_id, CommonAction::Activate)),
        )
        .route(
            "/comms/:comm_id/deactivate",
            put(|db, comm_id| comm_action(db, comm_id, CommonAction::Deactivate)),
        )
        .route(
            "/comms/:comm_id/toggle",
            put(|db, comm_id| comm_action(db, comm_id, CommonAction::Toggle)),
        )
}

fn doors_router() -> Router {
    Router::new()
        .route("/doors", get(list_doors))
        .route(
            "/doors/:door_id",
            get(|db, door_id| door_action(db, door_id, DoorAction::Report)),
        )
        .route(
            "/doors/:door_id/open",
            put(|db, door_id| door_action(db, door_id, DoorAction::Open)),
        )
        .route(
            "/doors/:door_id/close",
            put(|db, door_id| door_action(db, door_id, DoorAction::Close)),
        )
        .route(
            "/doors/:door_id/toggle",
            put(|db, door_id| door_action(db, door_id, DoorAction::Toggle)),
        )
}

fn environment_router() -> Router {
    Router::new().route("/env_ctrls", get(list_environments))
}

fn hydroponics_router() -> Router {
    Router::new()
        .route("/hydroponics", get(list_hydroponics))
        .route(
            "/hydroponics/:hydro_id",
            get(|db, hydro_id| hydroponics_action(db, hydro_id, CommonAction::Report)),
        )
        .route(
            "/hydroponics/:hydro_id/activate",
            put(|db, hydro_id| hydroponics_action(db, hydro_id, CommonAction::Activate)),
        )
        .route(
            "/hydroponics/:hydro_id/deactivate",
            put(|db, hydro_id| hydroponics_action(db, hydro_id, CommonAction::Deactivate)),
        )
        .route(
            "/hydroponics/:hydro_id/toggle",
            put(|db, hydro_id| hydroponics_action(db, hydro_id, CommonAction::Toggle)),
        )
}

fn power_router() -> Router {
    Router::new().route("/power", get(list_power))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let db_url = dotenvy::var("DATABASE_URL").context("DATABASE_URL must be set.")?;

    let db = PgPoolOptions::new()
        .connect(&db_url)
        .await
        .context("Failed to connect to database.")?;

    let app = Router::new()
        .merge(airlock_router())
        .merge(camera_router())
        .merge(comms_router())
        .merge(doors_router())
        .merge(environment_router())
        .merge(hydroponics_router())
        .merge(power_router())
        .layer(Extension(db));

    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

