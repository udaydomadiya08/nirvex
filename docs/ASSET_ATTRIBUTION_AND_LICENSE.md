# NIRMA: PROTOCOL — Piana v1.0.12 Toolkit Investigation, Clean-Room Asset Pipeline, and AAA Tactical Upgrade Report

## 1. Executive Summary & Architectural Scope

This report documents the complete forensic, legal, and technical investigation of the supplied `Piana.zip` archive (Blender add-on **Piana v1.0.12** by **Luviana**) and the resulting clean-room asset, rigging, shader, and Blender/glTF 2.0 pipeline upgrade integrated into **NIRMA: PROTOCOL**.

All technical patterns discovered in `Piana.zip` and `VALORANT_Map.blend` were rigorously classified into **Category A (Directly Reusable Under License)**, **Category B (Adaptable Workflow — Reimplemented Cleanly)**, and **Category C (Strictly Excluded / Prohibited)**. Zero proprietary Riot Games / VALORANT models, textures, animations, characters, weapons, map geometry, or encryption keys were extracted or used. Every character, weapon, skeleton, socket, material, and visual effect in `NIRMA: PROTOCOL` is 100% original and IP-safe.

## 2. Phase 1 — Exhaustive Inventory & Technical Analysis of `Piana.zip`

| File Path in `Piana.zip` | Size (Bytes) | Type / Format | Technical Purpose & Internal Mechanism |
| :--- | :---: | :--- | :--- |
| `Piana/__init__.py` | 1,289 | Python (`bpy`) | GPL-3.0 Blender 3.1.0+ add-on entry point (`bl_info`: version `1.0.12`, author `Luviana`). Invokes `auto_load.init()`, `register()`, and resets `addon_prefs.isInjected = False`. |
| `Piana/auto_load.py` | 4,773 | Python (`bpy`) | Automatic submodule scanner (`pkgutil.iter_modules`) and topological dependency sorter (`toposort`) registering `Panel`, `Operator`, `PropertyGroup`, `AddonPreferences`, `NodeTree`, and `UIList` classes. |
| `Piana/controls.py` | 3,825 | Python (`bpy`) | Builds 4 N-panel UI sections in `VIEW_3D`: `VIEW3D_PT_Piana` (Settings), `VIEW3D_PT_MapImporter`, `VIEW3D_PT_Animation` (`UB Setup`, `LB Setup`, `Face Setup`, `Twist Fix`, `Face Fix`), and `VIEW3D_PT_Others`. |
| `Piana/operators.py` | 6,458 | Python (`bpy`) | Implements `ImportMap` (`object.import_map`), 5 skeletal animation preparation operators (`val.ubbutton`, `val.lbbutton`, `val.facebutton`, `val.twistfix`, `val.facefix` credited to `twitter/r4tasan`), and `piana.runumodel`. |
| `Piana/prefs.py` | 3,954 | Python (`bpy`) | Defines `PianaPreferences` storing paths, decal/light toggles, `combineMethod` (`append` vs `link`), `textureControl` (`pack` vs `local`), and `usePerfPatch`. |
| `Piana/wip-umaplist.py` | 2,360 | Python (`bpy`) | Work-in-progress Blender `UIList` template (`MY_UL_List`, `ListItem`). |
| `Piana/mods/anims.py` | 1,586 | Python (`bpy`) | Recursive armature bone tree selector (`selectallchilds`, `selectchilds_recv`), subtree pose/keyframe reset (`reset_childs` on `Pelvis`, `Spine1`, `MasterWeaponAim`, `Head`), and twist-bone reset (`reset_twst` clearing transforms on all bones containing `'Twst'`). |
| `Piana/mods/liana_main.py` | 68,367 | Python (`bpy`) | Main scene assembler and procedural shader-graph builder (`set_materials`, `set_material`, `get_textures`, `import_umap`, `import_object`, `combine_umaps`, `post_setup`). Routes material JSON properties into 20 Blender `ShaderNodeTree` node groups, unpacks hex `OverrideVertexColors`, instances `PerInstanceSMData` under `-GRP` empties, and converts light energy (`POINT`, `SPOT`, `AREA`, `SUN`) into Blender Watts. |
| `Piana/mods/liana/blender.py` | 11,500 | Python (`bpy`) | Scene cleanup (`clean_scene`), duplicate node-group/material deduplication (`clear_duplicate_node_groups`, `remove_duplicate_mats`), Unreal-to-Blender centimeter scale (`* 0.01`) and quaternion/Euler conversion (`game_to_blender_rotations`, `set_properties`). |
| `Piana/mods/liana/helpers.py` | 7,663 | Python (`bpy`) | Defines `Settings`, `Map`, and `BlendMode` (`OPAQUE`, `CLIP`, `BLEND`, `HASHED`), plus the list of 19 shader node-group names imported from `VALORANT_Map.blend`. |
| `Piana/mods/liana/importer_xay.py` | 5,403 | Python (`bpy`) | Custom binary static mesh importer (`magic == 0x02594158`), reading 32-byte interleaved vertex/normal/UV records, multi-UV layers (`UVMap_0..N`), material face sections, split custom normals, and linear-to-sRGB vertex colors (`color_linear_to_srgb`). |
| `Piana/mods/liana/valorant.py` | 6,201 | Python | Filters UMAP actor JSONs (`StaticMeshComponent`, `InstancedStaticMeshComponent`, `HierarchicalInstancedStaticMeshComponent`, `DecalComponent`, light components) and resolves material override paths. |
| `Piana/ui/funcs.py` & `props.py` | 3,886 | Python | Queries local Windows installation metadata (`valorant.live.product_settings.yaml`) and version strings. |
| `Piana/utils/common.py` | 1,140 | Python | Standard Python `logging` formatter and JSON loader. |
| `Piana/assets/VALORANT_Map.blend` | 1,816,776 | Blender v3.01 Binary | Contains 20 pre-authored Cycles/EEVEE `ShaderNodeTree` (`NT`) datablocks (`NTVALORANT_Base`, `NTVALORANT_Blend`, `NTVALORANT_ColorTint`, `NTVALORANT_Decal`, `NTVALORANT_Emissive`, `NTVALORANT_Emissive_Scroll`, `NTVALORANT_Glass`, `NTVALORANT_Hologram`, `NTVALORANT_Lightshift`, `NTVALORANT_MRA_Splitter`, `NTVALORANT_Normal_Fix`, `NTVALORANT_Screen`, `NTVALORANT_Skybox`, `NTVALORANT_SpriteGlow`, `NTVALORANT_Ventsmoke`, `NTVALORANT_Ventsmoke_Mapping`, `NTVALORANT_W/V_Mapping`, `NTVALORANT_Waterfall`, `NTVALORANT_Waterfall_Mapping`, `NTWarmth (Gaffer)`). |
| `Piana/assets/umaps.json` | 5,903 | JSON | Dictionary mapping VALORANT map codenames to UMAP partition lists. |
| `Piana/tools/io_import_scene_unreal_psa_psk_280.py` | 87,788 | Python (`bpy`) | Open-source GPL-2.0+ Blender 2.80+ Unreal `.psk`/`.pskx` skeletal mesh and `.psa` animation importer (authors: Darknet, flufy3d, camg188, befzz, floxay) with `SCALEKEYS` support. |
| `Piana/tools/injector.py` & `BlenderPerfPatch.dll` | 26,227 | Python + Win32 DLL | Windows `kernel32` (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) DLL injector for patching Blender runtime performance. |
| `Piana/tools/cue4extractor.exe`, `umodel.exe`, `CUE4Parse-Natives.dll`, `libSkiaSharp.dll`, `SDL2.dll` | 16,388,987 | Win32/Win64 Binaries | External command-line extractors for decrypting Unreal Engine `.pak` files. |

## 3. Phase 2 — Legal, Technical, and Architectural Classification (Categories A, B, C)

- **Category A — Directly Reusable Under Open-Source License (GPL-2.0 / GPL-3.0 / Clean Utility Equivalence)**:
  - `auto_load.py` (topological class registration pattern), `mods/liana/blender.py` (material/node-group deduplication), and `tools/io_import_scene_unreal_psa_psk_280.py` (general PSK/PSA skeletal bone quaternion reference).
- **Category B — Adaptable Technical Workflows & Shader/Rig Architecture (Reimplemented Cleanly in Original Code)**:
  - `NirmaTactical_MRA_Splitter` (clean-room packed Metallic-Roughness-AO texture evaluation with warm `AO Color` cavity tinting).
  - `NirmaTactical_Normal_Calibration` (clean-room OpenGL/DirectX tangent-space normal Y-calibration and per-material relief scaling).
  - `NirmaTactical_MLB_Readability` (clean-room Minimum Light Brightness shadow floor ensuring competitive target readability).
  - **28-Bone Piana Clean-Room Rig**: Upper/Lower-body split via `aim_pitch_bone` (`MasterWeaponAim` equivalent), `forearm_twist_L/R` axial roll stabilization (`*Twst*` equivalent), 2-bone analytical arm IK, and stride-locked `toe_L/R` push-off kinematics.
- **Category C — Strictly Excluded / Prohibited (`DO NOT USE`)**:
  - `cue4extractor.exe`, `umodel.exe`, `CUE4Parse-Natives.dll`, hardcoded VALORANT AES-256 key, `ui/funcs.py`, `umaps.json`, and `injector.py` / `BlenderPerfPatch.dll`.

## 4. Summary of Upgraded Assets & Verification Results

- **5 Playable Hero Agents (28-Bone Articulated Rigs)**: `VAJRA` (Duelist), `DRISHTI` (Initiator), `PRALAY` (Controller), `KAVACH` (Sentinel), and new 5th Hero Agent `AGNI` (Thermal Controller).
- **11 Tactical Weapons (6 Standardized Sockets)**: `vanguard_ar` (Vandal), `surya_carbine` (Phantom), `spectre_smg` (Spectre), `breacher_sg` (Bucky/Judge), `agni_lmg` (Odin), `garuda_dmr` (Guardian), `vajra_sniper` (Operator), `sidearm_9mm` (Classic), `chhaya_pistol` (Ghost), `rudra_revolver` (Sheriff), and `katar_knife` (Melee), each equipped with `grip_primary`, `grip_secondary`, `muzzle_socket`, `magazine_socket`, `scope_mount`, and `shell_eject_socket`.
- **1st-Person Bore-to-Crosshair Ray Convergence**: `PlayerController.updateCameraTransform` dynamically converges the 1st-person weapon bore axis onto the center crosshair ray (`rot.x = +0.00911 rad, rot.y = +0.00956 rad`).
- **Interactive In-Game Studio (`[U]`)**: Press `[U]` or click **[U] Piana 3D Asset & Rig Studio** on the Main Menu to inspect any Hero or Weapon on a live 360° 3D Turntable with toggleable Bones/Sockets, Wireframe, Pose cycling, and all 3 Piana Audit & QA tabs.
