// SPDX-License-Identifier: Apache-2.0
use fe11::*;

#[test]
fn windows_loader_search_directories() {
    let base = || WindowsLoaderSearchDirectories {
        application_directory: std::path::PathBuf::from(""),
        requested_module: std::path::PathBuf::from(""),
        selection: WindowsDependencySearch::ApplicationConfigured,
        system_directory: std::path::PathBuf::from(""),
    };
    let samples: [std::path::PathBuf; 4] = [
        std::path::PathBuf::from(""),
        std::path::PathBuf::from("public"),
        std::path::PathBuf::from("été"),
        std::path::PathBuf::from("x\0y"),
    ];
    for expected in samples {
        let instance = WindowsLoaderSearchDirectories {
            application_directory: expected.clone(),
            ..base()
        };
        assert_eq!(instance.application_directory, expected);
    }
    let samples: [std::path::PathBuf; 4] = [
        std::path::PathBuf::from(""),
        std::path::PathBuf::from("public"),
        std::path::PathBuf::from("été"),
        std::path::PathBuf::from("x\0y"),
    ];
    for expected in samples {
        let instance = WindowsLoaderSearchDirectories {
            requested_module: expected.clone(),
            ..base()
        };
        assert_eq!(instance.requested_module, expected);
    }
    let samples: [WindowsDependencySearch; 2] = [
        WindowsDependencySearch::ApplicationConfigured,
        WindowsDependencySearch::Directories {
            application_added_directories: true,
            application_directory: true,
            module_directory: true,
            system32: true,
        },
    ];
    for expected in samples {
        let instance = WindowsLoaderSearchDirectories {
            selection: expected.clone(),
            ..base()
        };
        assert_eq!(instance.selection, expected);
    }
    let samples: [std::path::PathBuf; 4] = [
        std::path::PathBuf::from(""),
        std::path::PathBuf::from("public"),
        std::path::PathBuf::from("été"),
        std::path::PathBuf::from("x\0y"),
    ];
    for expected in samples {
        let instance = WindowsLoaderSearchDirectories {
            system_directory: expected.clone(),
            ..base()
        };
        assert_eq!(instance.system_directory, expected);
    }
}
