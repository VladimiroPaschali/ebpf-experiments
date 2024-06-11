//! # [Ratatui] `BarChart` example
//!
//! The latest version of this example is available in the [examples] folder in the repository.
//!
//! Please note that the examples are designed to be run against the `main` branch of the Github
//! repository. This means that you may not be able to compile with the latest release version on
//! crates.io, or the one that you have installed locally.
//!
//! See the [examples readme] for more information on finding examples that match the version of the
//! library you are using.
//!
//! [Ratatui]: https://github.com/ratatui-org/ratatui
//! [examples]: https://github.com/ratatui-org/ratatui/blob/main/examples
//! [examples readme]: https://github.com/ratatui-org/ratatui/blob/main/examples/README.md

use std::{
    borrow::Borrow,
    error::Error,
    io,
    time::{Duration, Instant},
};

use std::string::String;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Bar, BarChart, BarGroup, Block, Paragraph},
};

mod bpf;
use bpf::{get_data_from_map, get_map_by_id, get_map_id};

struct App<'a> {
    data: Vec<Bar<'a>>,
    map_name: &'a str,
}

impl<'a> App<'a> {
    fn new() -> Self {
        let map_name = "percpu_hist";
        let map_id = get_map_id(map_name).unwrap();
        let map = get_map_by_id(map_id).unwrap();
        let zero: &[u8] = &[0; 4];
        let data = get_data_from_map(&map, zero, 21);
        println!("{:?}", data);
        let group: Vec<Bar> = data
            .iter()
            .enumerate()
            .map(|(index, value)| Bar::default().value(*value).text_value(index.to_string()))
            .collect();
        Self {
            data: group,
            map_name,
        }
    }

    fn on_tick(&mut self) {
        let value = self.data.pop().unwrap();
        self.data.insert(0, value);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let app = App::new();

    //println!("-----{:?}", app.data);

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app and run it
    let tick_rate = Duration::from_millis(250);
    // let res = run_app(&mut terminal, app, tick_rate);

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    /*
    if let Err(err) = res {
        println!("{err:?}");
    } */

    Ok(())
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
    tick_rate: Duration,
) -> io::Result<()> {
    let mut last_tick = Instant::now();
    loop {
        terminal.draw(|f| ui(f, &app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    return Ok(());
                }
            }
        }
        /*         if last_tick.elapsed() >= tick_rate {
            app.on_tick();
            last_tick = Instant::now();
        } */
    }
}

fn ui(frame: &mut Frame, app: &App) {
    let vertical = Layout::vertical([Constraint::Percentage(100), Constraint::Ratio(2, 3)]);
    let [top, bottom] = vertical.areas(frame.size());

    let barchart = BarChart::default()
        .block(Block::bordered().title("Data1"))
        .data(BarGroup::default().bars(&app.data))
        .bar_width(9)
        .bar_style(Style::default().fg(Color::Yellow))
        .value_style(Style::default().fg(Color::Black).bg(Color::Yellow));

    frame.render_widget(barchart, top);
}
